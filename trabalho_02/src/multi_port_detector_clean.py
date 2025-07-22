"""
Detector Multi-Porta de Ataques DDoS

Sistema de detecção de ataques DDoS que monitora múltiplas portas
simultaneamente e identifica padrões de tráfego suspeitos.
"""

import logging
import time
from collections import defaultdict, deque
from datetime import datetime

from utils import safe_log_message

try:
    from scapy.all import sniff, IP, TCP, UDP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy não disponível - Modo simulação ativado")


class MultiPortDetector:
    """Detector de ataques DDoS multi-porta."""
    
    def __init__(self, config, port_manager, notification_system):
        self.config = config
        self.port_manager = port_manager
        self.notification_system = notification_system
        
        self.time_window = config['detection']['time_window']
        self.monitored_ports = config['detection']['ports']
        
        self.port_ip_history = defaultdict(lambda: defaultdict(deque))
        self.port_statistics = defaultdict(lambda: {
            'total_packets': 0,
            'unique_ips': set(),
            'attack_detected': False,
            'last_attack_time': None,
            'first_packet_time': None
        })
        
        self.port_status = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.logger.info(f"Detector inicializado para portas: {list(self.monitored_ports.keys())}")

    def packet_callback(self, packet):
        """Processa pacotes capturados."""
        if not SCAPY_AVAILABLE:
            return
            
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            
            if dst_port in self.monitored_ports:
                self._process_packet(src_ip, dst_port)

    def _process_packet(self, source_ip, destination_port):
        """Analisa pacote individual."""
        current_time = time.time()
        
        if self.port_manager.is_whitelisted(source_ip):
            return
        
        self.port_ip_history[destination_port][source_ip].append(current_time)
        self._cleanup_old_timestamps(destination_port, source_ip, current_time)
        self._update_port_statistics(destination_port, source_ip)
        self._check_for_ddos_attack(source_ip, destination_port, current_time)

    def _cleanup_old_timestamps(self, port, ip, current_time):
        """Remove timestamps antigos."""
        while (self.port_ip_history[port][ip] and 
               current_time - self.port_ip_history[port][ip][0] > self.time_window):
            self.port_ip_history[port][ip].popleft()

    def _check_for_ddos_attack(self, source_ip, port, current_time):
        """Verifica se padrão indica ataque DDoS."""
        packet_count = len(self.port_ip_history[port][source_ip])
        max_allowed = self.monitored_ports[port]['max_requests']
        
        if packet_count > max_allowed:
            self._handle_ddos_attack(source_ip, port, packet_count)

    def _update_port_statistics(self, port, source_ip):
        """Atualiza estatísticas da porta."""
        stats = self.port_statistics[port]
        stats['total_packets'] += 1
        stats['unique_ips'].add(source_ip)
        
        if stats['first_packet_time'] is None:
            stats['first_packet_time'] = time.time()
        
        self._update_port_status(port)

    def _update_port_status(self, port):
        """Atualiza status para dashboard."""
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
        """Processa detecção de ataque DDoS."""
        port_config = self.monitored_ports[dst_port]
        
        self.port_statistics[dst_port]['attack_detected'] = True
        self.port_statistics[dst_port]['last_attack'] = time.time()
        
        self.logger.warning(
            f"🚨 ATAQUE DDoS DETECTADO! "
            f"IP: {src_ip} | Porta: {dst_port} ({port_config['protocol']}) | "
            f"Pacotes: {packet_count} | Limite: {port_config['max_requests']}"
        )
        
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
        
        self.notification_system.send_alert(attack_data)
        
        if dst_port not in self.port_manager.blocked_ports:
            self.port_manager.block_port(dst_port)
        
        self._update_port_status(dst_port)

    def start_monitoring(self):
        """Inicia monitoramento de pacotes."""
        self.logger.info(f"Iniciando monitoramento de portas: {list(self.monitored_ports.keys())}")
        
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy não disponível - Iniciando modo simulação")
            self._start_simulation_mode()
            return
        
        try:
            self._configure_scapy_compatibility()
            port_filter = self._create_packet_filter()
            
            self.logger.info("Iniciando captura de pacotes...")
            sniff(
                prn=self.packet_callback,
                filter=port_filter,
                store=0
            )
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar monitoramento: {e}")
            self.logger.warning("Continuando em modo simulação...")
            self._start_simulation_mode()

    def _configure_scapy_compatibility(self):
        """Configura Scapy para compatibilidade."""
        if SCAPY_AVAILABLE:
            try:
                from scapy.all import L3RawSocket
                conf.L3socket = L3RawSocket
            except:
                pass

    def _create_packet_filter(self):
        """Cria filtro BPF para portas monitoradas."""
        port_filters = [f"port {port}" for port in self.monitored_ports.keys()]
        return " or ".join(port_filters)

    def _start_simulation_mode(self):
        """Modo simulação quando Scapy não disponível."""
        self.logger.info("Modo simulação ativado - Detector funcionando sem captura real")
        while True:
            time.sleep(1)

    def get_statistics(self):
        """Retorna estatísticas atuais do sistema."""
        return {
            'port_status': self.port_status,
            'total_monitored_ports': len(self.monitored_ports),
            'active_attacks': sum(1 for stats in self.port_statistics.values() if stats['attack_detected']),
            'total_packets': sum(stats['total_packets'] for stats in self.port_statistics.values())
        }
