"""
Sistema de Notificações para Detecção DDoS

Sistema responsável por alertas e notificações de eventos de segurança.
"""

import logging
import os
import time
from datetime import datetime


class NotificationSystem:
    """Sistema de notificações para eventos de segurança."""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        if config['notifications']['log_file']['enabled']:
            self._setup_alert_logging()
    
    def _setup_alert_logging(self):
        """Configura logging específico para alertas."""
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        self.alert_logger = logging.getLogger('ddos_alerts')
        self.alert_logger.setLevel(logging.WARNING)
        
        log_file_path = os.path.join(log_dir, 'security_alerts.log')
        file_handler = logging.FileHandler(log_file_path)
        formatter = logging.Formatter(
            '%(asctime)s - SECURITY_ALERT - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        self.alert_logger.addHandler(file_handler)
    
    def send_alert(self, attack_data):
        """Envia alerta de ataque detectado."""
        if self.config['notifications']['console']['enabled']:
            self._console_alert(attack_data)
        
        if self.config['notifications']['log_file']['enabled']:
            self._log_alert(attack_data)
        
        self._play_alert_sound()
    
    def _console_alert(self, data):
        """Exibe alerta no console."""
        criticality = "🔴 CRÍTICO" if data['critical'] else "🟡 ALERTA"
        
        print("\n" + "="*60)
        print(f"{criticality} - ATAQUE DDoS DETECTADO!")
        print("="*60)
        print(f"🎯 Porta Atacada: {data['port']} ({data['protocol']})")
        print(f"📝 Descrição: {data['description']}")
        print(f"🌐 IP Atacante: {data['ip']}")
        print(f"📊 Pacotes Detectados: {data['packet_count']}")
        print(f"⚠️ Limite Permitido: {data['max_allowed']}")
        print(f"⏰ Timestamp: {data['timestamp']}")
        print(f"🔒 Ação: Porta {data['port']} foi BLOQUEADA")
        print("="*60 + "\n")
    
    def _log_alert(self, data):
        """Registra alerta em arquivo de log."""
        log_message = (
            f"DDoS_ATTACK | "
            f"PORT:{data['port']} | "
            f"PROTOCOL:{data['protocol']} | "
            f"IP:{data['ip']} | "
            f"PACKETS:{data['packet_count']} | "
            f"LIMIT:{data['max_allowed']} | "
            f"CRITICAL:{data['critical']} | "
            f"ACTION:PORT_BLOCKED"
        )
        
        self.alert_logger.warning(log_message)
    
    def _play_alert_sound(self):
        """Toca som de alerta."""
        try:
            if os.name == 'nt':  # Windows
                import winsound
                for _ in range(3):
                    winsound.Beep(1000, 300)
                    time.sleep(0.1)
            else:  # Linux
                os.system('beep -f 1000 -l 300 -r 3')
        except:
            pass
    
    def send_status_update(self, status_data):
        """Envia atualização de status."""
        self.logger.info(f"Status das portas: {status_data}")
