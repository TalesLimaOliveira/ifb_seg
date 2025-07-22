"""
Detector Multi-Porta de Ataques DDoS

Este módulo implementa um sistema avançado de detecção de ataques DDoS
que monitora múltiplas portas de rede simultaneamente usando captura 
de pacotes em tempo real e análise de padrões de tráfego.

Classes:
    MultiPortDetector: Detector principal de ataques DDoS

Funcionalidades:
    - Monitoramento simultâneo de múltiplas portas
    - Detecção baseada em thresholds configuráveis
    - Coleta de estatísticas detalhadas por porta
    - Suporte a whitelist de IPs confiáveis
    - Modo simulação quando scapy não está disponível

Dependencies:
    - scapy: Para captura de pacotes (opcional)
    - threading: Para processamento assíncrono

Author: Sistema de Detecção DDoS - IFB
"""

import time
import logging
import os
from collections import defaultdict, deque
from threading import Thread
from datetime import datetime

# Importações condicionais para compatibilidade
try:
    from scapy.all import sniff, IP, TCP, UDP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy não disponível - Modo simulação ativado")


class MultiPortDetector:
    """
    Detector avançado de ataques DDoS para múltiplas portas de rede.
    
    Esta classe implementa um sistema de monitoramento que captura pacotes
    de rede em tempo real e analisa padrões de tráfego para detectar
    possíveis ataques DDoS em portas específicas.
    
    Attributes:
        config (dict): Configurações do sistema
        port_manager (PortManager): Gerenciador de controle de portas
        notification_system (NotificationSystem): Sistema de notificações
        monitored_ports (dict): Portas sendo monitoradas
        port_statistics (dict): Estatísticas coletadas por porta
        simulation_mode (bool): Indica se está em modo simulação
    """
    
    def __init__(self, config, port_manager, notification_system):
        """
        Inicializa o detector multi-porta.
        
        Args:
            config (dict): Configurações do sistema carregadas do config.yaml
            port_manager (PortManager): Instância do gerenciador de portas para bloqueios
            notification_system (NotificationSystem): Sistema para envio de alertas
        """
        self.config = config
        self.port_manager = port_manager
        self.notification_system = notification_system
        
        # Configurações de detecção extraídas do config
        self.time_window = config['detection']['time_window']
        self.monitored_ports = config['detection']['ports']
        
        # Estruturas de dados para monitoramento
        # Histórico: {porta: {ip: deque_timestamps}}
        self.port_ip_history = defaultdict(lambda: defaultdict(deque))
        
        # Estatísticas por porta
        self.port_statistics = defaultdict(lambda: {
            'total_packets': 0,
            'unique_ips': set(),
            'attack_detected': False,
            'last_attack_time': None,
            'first_packet_time': None
        })
        
        # Status das portas para dashboard
        self.port_status = {}
        
        # Configurar logging
        self._setup_logging()
        
        try:
            self.logger.info(f"🔧 Detector inicializado para portas: {list(self.monitored_ports.keys())}")
        except UnicodeEncodeError:
            self.logger.info(f"Detector inicializado para portas: {list(self.monitored_ports.keys())}")
        
    def _setup_logging(self):
        """
        Configura sistema de logging para o detector.
        
        Cria logs específicos para o detector na pasta logs/
        """
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # Configurar handler específico se ainda não configurado
        self.logger = logging.getLogger(self.__class__.__name__)
        if not self.logger.handlers:
            handler = logging.FileHandler(os.path.join(log_dir, 'detector.log'))
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        
    def packet_callback(self, packet):
        """
        Callback principal para processamento de pacotes capturados.
        
        Esta função é chamada para cada pacote capturado pela interface de rede
        e realiza a análise inicial para determinar se o pacote deve ser processado.
        
        Args:
            packet: Objeto de pacote capturado pelo Scapy
        """
        if not SCAPY_AVAILABLE:
            return
            
        # Verifica se é um pacote IP com TCP ou UDP
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            
            # Processa apenas portas monitoradas
            if dst_port in self.monitored_ports:
                self._process_packet(src_ip, dst_port)
    
    def _process_packet(self, source_ip, destination_port):
        """
        Processa um pacote para uma porta específica e realiza análise de DDoS.
        
        Args:
            source_ip (str): IP de origem do pacote
            destination_port (int): Porta de destino do pacote
        """
        current_time = time.time()
        
        # Ignora IPs da whitelist para evitar falsos positivos
        if self.port_manager.is_whitelisted(source_ip):
            return
        
        # Adiciona timestamp ao histórico da porta/IP
        self.port_ip_history[destination_port][source_ip].append(current_time)
        
        # Limpa timestamps antigos (fora da janela de tempo)
        self._cleanup_old_timestamps(destination_port, source_ip, current_time)
        
        # Atualiza estatísticas da porta
        self._update_port_statistics(destination_port, source_ip)
        
        # Verifica se há indícios de ataque DDoS
        self._check_for_ddos_attack(source_ip, destination_port, current_time)
    
    def _cleanup_old_timestamps(self, port, ip, current_time):
        """
        Remove timestamps antigos que estão fora da janela de tempo.
        
        Args:
            port (int): Porta sendo analisada
            ip (str): IP sendo analisado
            current_time (float): Timestamp atual
        """
        while (self.port_ip_history[port][ip] and 
               current_time - self.port_ip_history[port][ip][0] > self.time_window):
            self.port_ip_history[port][ip].popleft()
    
    def _check_for_ddos_attack(self, source_ip, port, current_time):
        """
        Verifica se o padrão de tráfego indica um ataque DDoS.
        
        Args:
            source_ip (str): IP de origem
            port (int): Porta de destino
            current_time (float): Timestamp atual
        """
        packet_count = len(self.port_ip_history[port][source_ip])
        max_allowed = self.monitored_ports[port]['max_requests']
        
        if packet_count > max_allowed:
            self._handle_ddos_attack(source_ip, port, packet_count)
    
    def _update_port_statistics(self, port, source_ip):
        """
        Atualiza estatísticas de uma porta específica.
        
        Args:
            port (int): Porta a ser atualizada
            source_ip (str): IP de origem do pacote
        """
        stats = self.port_statistics[port]
        stats['total_packets'] += 1
        stats['unique_ips'].add(source_ip)
        
        # Marca primeiro pacote se ainda não foi definido
        if stats['first_packet_time'] is None:
            stats['first_packet_time'] = time.time()
        
        # Atualiza status para dashboard
        self._update_port_dashboard_status(port)
    
    def _update_port_dashboard_status(self, port):
        """
        Atualiza status da porta para dashboard.
        
        Args:
            port (int): Porta a ser atualizada
        """
        stats = self.port_statistics[port]
        config_port = self.monitored_ports[port]
        
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
        """Atualiza status da porta para dashboard"""
        stats = self.port_statistics[port]
        config_port = self.monitored_ports[port]
        
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
        """Trata detecção de ataque DDoS"""
        port_config = self.monitored_ports[dst_port]
        
        # Marca ataque como detectado
        self.port_statistics[dst_port]['attack_detected'] = True
        self.port_statistics[dst_port]['last_attack'] = time.time()
        
        # Log do ataque
        self.logger.warning(
            f"🚨 ATAQUE DDoS DETECTADO! "
            f"IP: {src_ip} | Porta: {dst_port} ({port_config['protocol']}) | "
            f"Pacotes: {packet_count} | Limite: {port_config['max_requests']}"
        )
        
        # Dados do ataque para notificação
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
        
        # Envia notificação
        self.notification_system.send_alert(attack_data)
        
        # Bloqueia a porta se ainda não estiver bloqueada
        if dst_port not in self.port_manager.blocked_ports:
            self.port_manager.block_port(dst_port)
        
        # Atualiza status da porta
        self._update_port_status(dst_port)
    
    def start_monitoring(self):
        """
        Inicia o monitoramento de pacotes em tempo real.
        
        Configura e inicia a captura de pacotes usando Scapy, com fallback
        para modo simulação caso o Scapy não esteja disponível.
        """
        try:
            self.logger.info(f"🔍 Iniciando monitoramento de portas: {list(self.monitored_ports.keys())}")
        except UnicodeEncodeError:
            self.logger.info(f"Iniciando monitoramento de portas: {list(self.monitored_ports.keys())}")
        
        if not SCAPY_AVAILABLE:
            try:
                self.logger.warning("⚠️ Scapy não disponível - Iniciando modo simulação")
            except UnicodeEncodeError:
                self.logger.warning("Scapy não disponível - Iniciando modo simulação")
            self._start_simulation_mode()
            return
        
        try:
            # Configura scapy para compatibilidade com Windows
            self._configure_scapy_compatibility()
            
            # Cria filtro para capturar apenas portas monitoradas
            port_filter = self._create_packet_filter()
            
            # Inicia captura de pacotes
            self.logger.info("🌐 Iniciando captura de pacotes...")
            if SCAPY_AVAILABLE:
                sniff(
                    prn=self.packet_callback,
                    filter=port_filter,
                    store=0  # Não armazena pacotes para economizar memória
                )
            
        except Exception as e:
            self.logger.error(f"❌ Erro ao iniciar monitoramento: {e}")
            self.logger.warning("⚠️ Continuando em modo simulação...")
            self._start_simulation_mode()
    
    def _configure_scapy_compatibility(self):
        """Configura Scapy para compatibilidade cross-platform."""
        if SCAPY_AVAILABLE:
            try:
                from scapy.all import L3RawSocket
                conf.L3socket = L3RawSocket
            except:
                pass  # Ignora se não conseguir configurar
    
    def _create_packet_filter(self):
        """
        Cria filtro BPF para capturar apenas pacotes das portas monitoradas.
        
        Returns:
            str: String de filtro BPF
        """
        port_filters = [f"port {port}" for port in self.monitored_ports.keys()]
        return " or ".join(port_filters)
    
    def _start_simulation_mode(self):
        """Inicia modo de simulação quando Scapy não está disponível."""
        self.logger.info("🎭 Modo simulação ativado - Detector funcionando sem captura real")
        # Em modo simulação, apenas mantém as estruturas ativas
        while True:
            time.sleep(1)
    
    def get_statistics(self):
        """Retorna estatísticas atuais"""
        return {
            'port_status': self.port_status,
            'total_monitored_ports': len(self.monitored_ports),
            'active_attacks': sum(1 for stats in self.port_statistics.values() if stats['attack_detected']),
            'total_packets': sum(stats['total_packets'] for stats in self.port_statistics.values())
        }
