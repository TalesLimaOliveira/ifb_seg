import time        
import logging     
import os         
from collections import defaultdict, deque 
from threading import Thread        
from datetime import datetime       
from utils import safe_log_message     

# Tentativa de importar scapy (pode não estar disponível)
try:
    from scapy.all import sniff, IP, TCP, UDP, conf
    SCAPY_AVAILABLE = True    # Flag indicando que scapy está disponível
except ImportError:
    SCAPY_AVAILABLE = False   # Modo simulação se scapy não estiver instalado
    print("⚠️ Scapy não disponível - Modo simulação ativado")


class MultiPortDetector:
       
    def __init__(self, config, port_manager, notification_system):
        # Armazena referências dos componentes do sistema
        self.config = config
        self.port_manager = port_manager
        self.notification_system = notification_system
        
        # Extrai configurações específicas de detecção
        self.time_window = config['detection']['time_window']
        self.monitored_ports = config['detection']['ports']
        
        # Estruturas de dados para histórico de pacotes
        # Formato: {porta: {ip: deque_com_timestamps}}
        self.port_ip_history = defaultdict(lambda: defaultdict(deque))
        
        # Estatísticas detalhadas por porta
        self.port_statistics = defaultdict(lambda: {
            'total_packets': 0,      # Total de pacotes recebidos
            'unique_ips': set(),     # IPs únicos que acessaram a porta
            'attack_detected': False, # Se ataque foi detectado
            'last_attack_time': None, # Timestamp do último ataque
            'first_packet_time': None # Timestamp do primeiro pacote
        })
        
        # Status atual das portas (para dashboard)
        self.port_status = {}
        
        # Configura sistema de logging
        self._setup_logging()
        
        # Log de inicialização (com tratamento de encoding)
        try:
            self.logger.info(safe_log_message(f"🔧 Detector inicializado para portas: {list(self.monitored_ports.keys())}"))
        except UnicodeEncodeError:
            self.logger.info(f"Detector inicializado para portas: {list(self.monitored_ports.keys())}")
        
    def _setup_logging(self):
        # Cria diretório de logs se não existir
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Configura logger específico para este componente
        self.logger = logging.getLogger(self.__class__.__name__)
        if not self.logger.handlers:  # Evita handlers duplicados
            # Cria handler para arquivo de log
            handler = logging.FileHandler(os.path.join(log_dir, 'detector.log'))
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        
    def packet_callback(self, packet):
        # Só processa se scapy estiver disponível
        if not SCAPY_AVAILABLE:
            return
            
        # Verifica se é pacote IP com protocolo TCP ou UDP
        if IP in packet and (TCP in packet or UDP in packet):
            # Extrai informações do pacote
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            
            # Só processa se a porta estiver sendo monitorada
            if dst_port in self.monitored_ports:
                self._process_packet(src_ip, dst_port)
    
    def _process_packet(self, source_ip, destination_port):
        # Marca timestamp atual
        current_time = time.time()
        
        # Ignora IPs da whitelist (IPs confiáveis)
        if self.port_manager.is_whitelisted(source_ip):
            return
        
        # Adiciona timestamp ao histórico desta combinação porta/IP
        self.port_ip_history[destination_port][source_ip].append(current_time)
        
        # Remove timestamps antigos que estão fora da janela de tempo
        self._cleanup_old_timestamps(destination_port, source_ip, current_time)
        
        # Atualiza estatísticas gerais da porta
        self._update_port_statistics(destination_port, source_ip)
        
        # Verifica se padrão indica ataque DDoS
        self._check_for_ddos_attack(source_ip, destination_port, current_time)
    
    def _cleanup_old_timestamps(self, port, ip, current_time):
        # Remove timestamps mais antigos que a janela de tempo configurada
        while (self.port_ip_history[port][ip] and 
               current_time - self.port_ip_history[port][ip][0] > self.time_window):
            self.port_ip_history[port][ip].popleft()  # Remove o mais antigo
    
    def _check_for_ddos_attack(self, source_ip, port, current_time):
        # Conta quantos pacotes este IP enviou na janela de tempo
        packet_count = len(self.port_ip_history[port][source_ip])
        # Busca o limite máximo configurado para esta porta
        max_allowed = self.monitored_ports[port]['max_requests']
        
        # Se exceder o limite, considera ataque DDoS
        if packet_count > max_allowed:
            self._handle_ddos_attack(source_ip, port, packet_count)
    
    def _update_port_statistics(self, port, source_ip):
        # Busca estatísticas da porta
        stats = self.port_statistics[port]
        # Incrementa contador total de pacotes
        stats['total_packets'] += 1
        # Adiciona IP ao conjunto de IPs únicos
        stats['unique_ips'].add(source_ip)
        
        # Marca timestamp do primeiro pacote se ainda não foi definido
        if stats['first_packet_time'] is None:
            stats['first_packet_time'] = time.time()
        
        # Atualiza status para dashboard
        self._update_port_dashboard_status(port)
    
    def _update_port_dashboard_status(self, port):
        # Busca estatísticas e configurações da porta
        stats = self.port_statistics[port]
        config_port = self.monitored_ports[port]
        
        # Monta dados completos do status da porta
        self.port_status[port] = {
            'port': port,
            'protocol': config_port['protocol'],
            'description': config_port['description'],
            'status': 'BLOCKED' if port in self.port_manager.blocked_ports else 'ACTIVE',
            'total_packets': stats['total_packets'],
            'unique_ips': len(stats['unique_ips']),
            'attack_detected': stats['attack_detected'],
            'last_update': datetime.now().isoformat(),
            'critical': config_port['critical']
        }
    
    def _update_port_status(self, port):
        # Busca dados necessários
        stats = self.port_statistics[port]
        config_port = self.monitored_ports[port]
        
        # Constrói objeto de status completo
        self.port_status[port] = {
            'port': port,
            'protocol': config_port['protocol'],
            'description': config_port['description'],
            'status': 'BLOCKED' if port in self.port_manager.blocked_ports else 'ACTIVE',
            'total_packets': stats['total_packets'],
            'unique_ips': len(stats['unique_ips']),
            'attack_detected': stats['attack_detected'],
            'last_update': datetime.now().isoformat(),
            'critical': config_port['critical']
        }
    
    def _handle_ddos_attack(self, src_ip, dst_port, packet_count):
        # Busca configurações da porta atacada
        port_config = self.monitored_ports[dst_port]
        
        # Marca ataque como detectado nas estatísticas
        self.port_statistics[dst_port]['attack_detected'] = True
        self.port_statistics[dst_port]['last_attack'] = time.time()
        
        # Registra alerta de ataque no log
        self.logger.warning(
            f"🚨 ATAQUE DDoS DETECTADO! "
            f"IP: {src_ip} | Porta: {dst_port} ({port_config['protocol']}) | "
            f"Pacotes: {packet_count} | Limite: {port_config['max_requests']}"
        )
        
        # Prepara dados do ataque para notificação
        attack_data = {
            'ip': src_ip,
            'port': dst_port,
            'protocol': port_config['protocol'],
            'description': port_config['description'],
            'packet_count': packet_count,
            'max_allowed': port_config['max_requests'],
            'timestamp': datetime.now().isoformat(),
            'critical': port_config['critical']
        }
        
        # Envia alerta através do sistema de notificações
        self.notification_system.send_alert(attack_data)
        
        # Bloqueia a porta automaticamente se ainda não estiver bloqueada
        if dst_port not in self.port_manager.blocked_ports:
            self.port_manager.block_port(dst_port)
        
        # Atualiza status da porta no dashboard
        self._update_port_status(dst_port)
    
    def start_monitoring(self):
        # Log de início do monitoramento (com tratamento de encoding)
        try:
            self.logger.info(safe_log_message(f"🔍 Iniciando monitoramento de portas: {list(self.monitored_ports.keys())}"))
        except UnicodeEncodeError:
            self.logger.info(f"Iniciando monitoramento de portas: {list(self.monitored_ports.keys())}")
        
        # Verifica se Scapy está disponível para captura real
        if not SCAPY_AVAILABLE:
            try:
                self.logger.warning(safe_log_message("⚠️ Scapy não disponível - Iniciando modo simulação"))
            except UnicodeEncodeError:
                self.logger.warning("Scapy não disponível - Iniciando modo simulação")
            self._start_simulation_mode()
            return
        
        try:
            # Configura Scapy para funcionar em diferentes sistemas
            self._configure_scapy_compatibility()
            
            # Cria filtro BPF para capturar apenas as portas monitoradas
            port_filter = self._create_packet_filter()
            
            # Inicia captura de pacotes em tempo real
            self.logger.info(safe_log_message("🌐 Iniciando captura de pacotes..."))
            if SCAPY_AVAILABLE:
                sniff(
                    prn=self.packet_callback,    # Callback para cada pacote
                    filter=port_filter,          # Filtro das portas
                    store=0                      # Não armazena para economizar memória
                )
            
        except Exception as e:
            # Em caso de erro, fallback para modo simulação
            self.logger.error(safe_log_message(f"❌ Erro ao iniciar monitoramento: {e}"))
            self.logger.warning(safe_log_message("⚠️ Continuando em modo simulação..."))
            self._start_simulation_mode()
    
    def _configure_scapy_compatibility(self):
        if SCAPY_AVAILABLE:
            try:
                # Tenta configurar socket raw para melhor compatibilidade
                from scapy.all import L3RawSocket
                conf.L3socket = L3RawSocket
            except:
                # Ignora se não conseguir configurar (continua com padrão)
                pass
    
    def _create_packet_filter(self):
        # Cria lista de filtros individuais para cada porta
        port_filters = [f"port {port}" for port in self.monitored_ports.keys()]
        # Junta todos os filtros com OR lógico
        return " or ".join(port_filters)
    
    def _start_simulation_mode(self):
        self.logger.info(safe_log_message("🎭 Modo simulação ativado - Detector funcionando sem captura real"))
        # Em modo simulação, mantém o processo ativo mas sem captura real
        while True:
            time.sleep(1)  # Loop infinito para manter processo vivo
    
    def get_statistics(self):
        return {
            'port_status': self.port_status,                           # Status de todas as portas
            'total_monitored_ports': len(self.monitored_ports),        # Total de portas monitoradas
            'active_attacks': sum(1 for stats in self.port_statistics.values() if stats['attack_detected']),  # Ataques ativos
            'total_packets': sum(stats['total_packets'] for stats in self.port_statistics.values())           # Total de pacotes processados
        }
