import json           
import logging        
import os     
from datetime import datetime    
from flask import Flask, render_template, request  
from flask_socketio import SocketIO, emit        
import threading    
import time         
from multi_port_attacker import MultiPortAttacker  
from utils import safe_log_message            

class DashboardServer:    
    def __init__(self, detector, port_manager):
        self.app = Flask(__name__, template_folder='../templates')
        self.app.config['SECRET_KEY'] = 'ddos_detection_secret_key'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        self.detector = detector
        self.port_manager = port_manager
        self.attacker = None
        self.attack_thread = None
        self.attack_active = False
        self.attack_target_port = None  # Porta específica sendo atacada
        
        # Registra callback para mudanças de status de porta
        if hasattr(self.port_manager, 'add_port_change_callback'):
            self.port_manager.add_port_change_callback(self._on_port_status_change)
        
        # Dados da simulação
        self.simulation_data = {
            'attacks': 0,
            'detections': 0,
            'blocks': 0,
            'start_time': None,
            'end_time': None,
            'events': []
        }
        
        # Configurar logging
        self._setup_logging()
        self._setup_routes()
        self._setup_socket_events()
    
    def _setup_logging(self):
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.FileHandler(
                os.path.join(log_dir, 'dashboard.log'), 
                encoding='utf-8'
            )
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def _serialize_datetime(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return obj
    
    def _prepare_simulation_data(self):
        data = self.simulation_data.copy()
        if data['start_time']:
            data['start_time'] = self._serialize_datetime(data['start_time'])
        if data['end_time']:
            data['end_time'] = self._serialize_datetime(data['end_time'])
        
        # Serializa eventos
        for event in data['events']:
            if 'timestamp' in event and isinstance(event['timestamp'], datetime):
                event['timestamp'] = self._serialize_datetime(event['timestamp'])
        
        return data
    
    def _on_port_status_change(self, port, status, reason):

        try:
            # Emite atualização imediata de status
            self._emit_status_update()
            
            # Emite log da mudança
            log_message = f"🔄 Porta {port}: {status} - {reason}"
            self._emit_log({
                'timestamp': datetime.now().isoformat(),
                'level': 'INFO' if status == 'ACTIVE' else 'WARNING',
                'message': log_message
            })
            
        except Exception as e:
            self.logger.error(f"Erro em callback de porta: {e}")
    
    def _setup_routes(self):
        
        @self.app.route('/')
        def index():
            """Página principal do dashboard."""
            return render_template('dashboard.html')
    
    def _setup_socket_events(self):
        
        @self.socketio.on('connect')
        def handle_connect():
            self.logger.info("Cliente conectado ao WebSocket")
            self._emit_status_update()
            # Emitir log de boas-vindas
            self._emit_log({
                'timestamp': datetime.now().isoformat(),
                'level': 'INFO',
                'message': '🔗 Cliente conectado ao dashboard - Sistema pronto para monitoramento'
            })
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            self.logger.info("Cliente desconectado do WebSocket")
        
        @self.socketio.on('get_status')
        def handle_get_status():
            self._emit_status_update()
        
        @self.socketio.on('start_attack')
        def handle_start_attack(data):
            port = data.get('port')
            if port and not self.attack_active:
                self._start_attack_simulation(port)
        
        @self.socketio.on('stop_attack')
        def handle_stop_attack():
            self._stop_attack_simulation()
        
        @self.socketio.on('toggle_port')
        def handle_toggle_port(data):
            port = data.get('port')
            if port:
                self._toggle_port_state(port)
    
    def _start_attack_simulation(self, target_port):
        try:
            self.attack_active = True
            self.attack_target_port = target_port  # Definir porta específica do ataque
            self.simulation_data['start_time'] = datetime.now()
            self.simulation_data['attacks'] += 1
            
            # Log do evento
            event = {
                'timestamp': datetime.now().isoformat(),
                'type': 'ATTACK_START',
                'port': target_port,
                'message': f'Simulação DDoS iniciada na porta {target_port}'
            }
            self.simulation_data['events'].append(event)
            
            # Não usar MultiPortAttacker que ataca múltiplas portas
            # Usar simulação simples focada apenas na porta selecionada
            
            # Iniciar ataque em thread separada
            self.attack_thread = threading.Thread(
                target=self._run_single_port_attack,
                args=(target_port,),
                daemon=True
            )
            self.attack_thread.start()
            
            # Emitir log
            log_message = f'🚨 Iniciando simulação de ataque DDoS APENAS na porta {target_port}'
            self._emit_log({
                'timestamp': datetime.now().isoformat(),
                'level': 'WARNING',
                'message': log_message
            })
            
            self.logger.warning(f"Simulação de ataque iniciada na porta {target_port}")
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar simulação: {e}")
            self.attack_active = False
    
    def _run_single_port_attack(self, target_port):
        try:
            import time
            import random
            
            # Simular ataque por 30 segundos com logs periódicos
            start_time = time.time()
            duration = 30
            cycle_count = 0
            
            # Log inicial
            self._emit_log({
                'timestamp': datetime.now().isoformat(),
                'level': 'WARNING',
                'message': f'🚨 INICIANDO ATAQUE DDOS FOCADO na porta {target_port} - Gerando múltiplos IPs atacantes'
            })
            
            while self.attack_active and (time.time() - start_time) < duration:
                cycle_count += 1
                
                # Gerar múltiplos IPs atacantes para simular DDoS real
                attack_ips = [
                    f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                    f"172.16.{random.randint(1,255)}.{random.randint(1,255)}",
                    f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                    f"203.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                ]
                
                # Gerar logs detalhados de ataque
                for i in range(random.randint(2, 4)):  # 2-4 logs por ciclo
                    fake_ip = random.choice(attack_ips)
                    packet_count = random.randint(100, 500)
                    connection_type = random.choice(['TCP SYN', 'UDP', 'HTTP GET', 'HTTPS'])
                    
                    log_message = f"🚨 ATAQUE DETECTADO - Porta {target_port} | {packet_count} pacotes {connection_type} de {fake_ip}"
                    self._emit_log({
                        'timestamp': datetime.now().isoformat(),
                        'level': 'CRITICAL',
                        'message': log_message
                    })
                
                # Log de resumo do ciclo
                total_packets = random.randint(1500, 3000)
                unique_ips = len(set(attack_ips))
                self._emit_log({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'WARNING',
                    'message': f"📊 Ciclo {cycle_count}: {total_packets} pacotes de {unique_ips} IPs únicos na porta {target_port}"
                })
                
                self.simulation_data['detections'] += 1
                
                # Simular bloqueio automático ocasionalmente
                if cycle_count % 5 == 0 and target_port not in self.port_manager.blocked_ports:
                    if random.random() < 0.6:  # 60% chance de bloquear
                        self.port_manager.block_port(target_port)
                        self.simulation_data['blocks'] += 1
                        
                        self._emit_log({
                            'timestamp': datetime.now().isoformat(),
                            'level': 'CRITICAL',
                            'message': f'🔒 Porta {target_port} BLOQUEADA automaticamente - Limiar excedido'
                        })
                
                # Forçar atualização do dashboard
                self._emit_status_update()
                
                time.sleep(3)  # Aguarda 3 segundos antes do próximo ciclo
                
        except Exception as e:
            self.logger.error(f"Erro durante ataque simulado: {e}")
            self._emit_log({
                'timestamp': datetime.now().isoformat(),
                'level': 'ERROR',
                'message': f'❌ Erro na simulação: {e}'
            })
        finally:
            if self.attack_active:
                self._stop_attack_simulation()
    
    def _stop_attack_simulation(self):
        try:
            self.attack_active = False
            self.attack_target_port = None  # Limpar porta alvo do ataque
            self.simulation_data['end_time'] = datetime.now()
            
            if self.attacker:
                self.attacker.stop_attack()
            
            # Log do evento
            event = {
                'timestamp': datetime.now().isoformat(),
                'type': 'ATTACK_STOP',
                'message': 'Simulação de ataque interrompida'
            }
            self.simulation_data['events'].append(event)
            
            # Emitir log
            log_message = '⏹️ Simulação de ataque interrompida'
            self._emit_log({
                'timestamp': datetime.now().isoformat(),
                'level': 'INFO',
                'message': log_message
            })
            
            self.logger.info("Simulação de ataque parada")
            
        except Exception as e:
            self.logger.error(f"Erro ao parar simulação: {e}")
    
    def _toggle_port_state(self, port):
        try:
            if port in self.port_manager.blocked_ports:
                # Desbloquear porta
                self.port_manager.unblock_port(port)
                action = "desbloqueada"
                self.simulation_data['blocks'] = max(0, self.simulation_data['blocks'] - 1)
            else:
                # Bloquear porta
                self.port_manager.block_port(port)
                action = "bloqueada"
                self.simulation_data['blocks'] += 1
            
            # Emitir log
            self._emit_log({
                'timestamp': datetime.now().isoformat(),
                'level': 'INFO',
                'message': f'🔐 Porta {port} {action} manualmente'
            })
            
            self.logger.info(f"Porta {port} {action} manualmente")
            
            # Forçar atualização de status após pequeno delay
            import threading
            def delayed_update():
                import time
                time.sleep(0.5)  # Aguarda 500ms
                self._emit_status_update()
            
            threading.Thread(target=delayed_update, daemon=True).start()
            
        except Exception as e:
            self.logger.error(f"Erro ao alternar porta {port}: {e}")
            # Emitir log de erro também
            self._emit_log({
                'timestamp': datetime.now().isoformat(),
                'level': 'ERROR',
                'message': f'❌ Erro ao alternar porta {port}: {e}'
            })
    
    def _emit_status_update(self):
        try:
            status_data = self._get_current_status()
            self.socketio.emit('system_update', status_data)
                
        except Exception as e:
            self.logger.error(f"Erro ao emitir atualização: {e}")
    
    def _emit_log(self, log_data):
        try:
            # Garantir que o timestamp está no formato correto
            if 'timestamp' not in log_data:
                log_data['timestamp'] = datetime.now().isoformat()
            
            # Criar versão sem emojis para o logger (console)
            clean_message = safe_log_message(log_data['message'])
            self.logger.info(f"[{log_data['level']}] {clean_message}")
            
            # Emitir via WebSocket com emojis intactos
            self.socketio.emit('new_log', log_data)
            
            # Força a emissão imediatamente
            self.socketio.sleep(0)
            
        except Exception as e:
            self.logger.error(f"Erro ao emitir log: {e}")
    
    def _get_current_status(self):
        try:
            # Portas fixas para monitoramento
            monitored_ports = [22, 80, 443]
            port_status = {}
            
            for port in monitored_ports:
                # Obter estatísticas da porta - usar dados simulados se detector não tiver dados reais
                if hasattr(self.detector, 'port_statistics') and self.detector.port_statistics:
                    stats = self.detector.port_statistics.get(port, {})
                else:
                    # Dados simulados para demonstração
                    import random
                    if self.attack_active and port == self.attack_target_port:
                        # Durante ataque: muito mais tráfego APENAS na porta alvo
                        base_packets = random.randint(500, 2000)
                        unique_ips_count = random.randint(15, 50)
                        attack_detected = random.choice([True, True, False])  # 66% chance de detectar
                    elif self.attack_active and port != self.attack_target_port:
                        # Outras portas durante ataque: tráfego normal baixo, SEM ataque
                        base_packets = random.randint(5, 25)  # Tráfego normal baixo
                        unique_ips_count = random.randint(1, 5)  # Poucos IPs únicos
                        attack_detected = False  # Definitivamente SEM ataque detectado
                    else:
                        # Sem ataque: tráfego zero ou muito baixo
                        base_packets = 0
                        unique_ips_count = 0
                        attack_detected = False
                    
                    stats = {
                        'total_packets': base_packets,
                        'unique_ips': set([f'192.168.1.{i}' for i in random.sample(range(1, min(255, unique_ips_count + 1)), unique_ips_count)]) if unique_ips_count > 0 else set(),
                        'attack_detected': attack_detected
                    }
                
                # Determinar status da porta - verificar se está realmente bloqueada
                is_blocked = port in self.port_manager.blocked_ports
                status = 'BLOCKED' if is_blocked else 'ACTIVE'
                
                port_status[port] = {
                    'port': port,
                    'status': status,
                    'total_packets': stats.get('total_packets', 0),
                    'unique_ips': len(stats.get('unique_ips', set())),
                    'attack_detected': stats.get('attack_detected', False),
                    'protocol': self._get_port_protocol(port),
                    'description': self._get_port_description(port),
                    'last_update': datetime.now().isoformat(),
                    'is_under_attack': self.attack_active and port == self.attack_target_port and attack_detected
                }
            
            return {
                'ports': port_status,
                'system': {
                    'attack_active': self.attack_active,
                    'attack_target_port': self.attack_target_port,  # Adicionar porta alvo
                    'total_blocked_ports': len(self.port_manager.blocked_ports),
                    'simulation_data': self._prepare_simulation_data(),
                    'simulation_summary': {
                        'total_events': len(self.simulation_data['events']),
                        'attacks': self.simulation_data['attacks'],
                        'detections': self.simulation_data['detections'],
                        'blocks': self.simulation_data['blocks']
                    }
                },
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao obter status: {e}")
            return {'error': str(e)}
    
    def _get_port_protocol(self, port):
        protocols = {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS'
        }
        return protocols.get(port, 'TCP')
    
    def _get_port_description(self, port):
        descriptions = {
            22: 'Secure Shell Protocol',
            80: 'HyperText Transfer Protocol',
            443: 'HTTP Secure'
        }
        return descriptions.get(port, 'Serviço Desconhecido')
    
    def start_background_updates(self):
        def update_loop():
            # Log inicial do sistema
            self._emit_log({
                'timestamp': datetime.now().isoformat(),
                'level': 'INFO',
                'message': '🚀 Sistema de Detecção DDoS iniciado - Monitorando portas 22, 80, 443'
            })
            
            update_count = 0
            while True:
                try:
                    time.sleep(3)  # Atualizar a cada 3 segundos
                    update_count += 1
                    
                    # A cada 20 atualizações (60 segundos), emitir log de status
                    if update_count % 20 == 0 and not self.attack_active:
                        self._emit_log({
                            'timestamp': datetime.now().isoformat(),
                            'level': 'INFO',
                            'message': f'✅ Sistema ativo - Monitoramento normal | Ciclo {update_count // 20}'
                        })
                    
                    # A cada 10 atualizações (30 segundos), simular tráfego normal
                    if update_count % 10 == 0 and not self.attack_active:
                        import random
                        normal_ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5']
                        normal_ip = random.choice(normal_ips)
                        port = random.choice([22, 80, 443])
                        activity = random.choice(['Acesso SSH', 'Requisição HTTP', 'Conexão HTTPS'])
                        
                        self._emit_log({
                            'timestamp': datetime.now().isoformat(),
                            'level': 'INFO',
                            'message': f'🌐 Tráfego normal - Porta {port}: {activity} de {normal_ip}'
                        })
                    
                    self._emit_status_update()
                except Exception as e:
                    self.logger.error(f"Erro no loop de atualização: {e}")
        
        update_thread = threading.Thread(target=update_loop, daemon=True)
        update_thread.start()
    
    def run(self, host='localhost', port=5000, debug=False):
        try:
            # Suprimir logs do werkzeug
            import logging
            werkzeug_logger = logging.getLogger('werkzeug')
            werkzeug_logger.setLevel(logging.ERROR)
            
            self.start_background_updates()
            self.socketio.run(self.app, host=host, port=port, debug=debug, 
                            use_reloader=False, log_output=False)
        except Exception as e:
            self.logger.error(f"Erro ao executar dashboard: {e}")
            raise
