
import logging
import subprocess
import time
from threading import Timer


class PortManager:
    def __init__(self, config):
        self.config = config
        self.blocked_ports = {}
        self.auto_unblock_time = config['blocking']['unblock_time']
        self.whitelist_ips = config['blocking']['whitelist_ips']
        self.port_change_callbacks = []
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def add_port_change_callback(self, callback):
        self.port_change_callbacks.append(callback)
    
    def _notify_port_change(self, port, status, reason=""):
        for callback in self.port_change_callbacks:
            try:
                callback(port, status, reason)
            except Exception as e:
                self.logger.error(f"Erro em callback de porta: {e}")
    
    def block_port(self, port, duration=None):
        if port in self.blocked_ports:
            return
            
        self.logger.warning(f"🔒 BLOQUEANDO PORTA {port} - Ataque DDoS detectado!")
        
        try:
            self._execute_iptables_block(port)
            self._register_blocked_port(port)
            self._notify_port_change(port, 'BLOCKED', 'DDoS Attack detected')
            self._schedule_auto_unblock(port, duration)
                      
        except subprocess.CalledProcessError as e:
            self.logger.error(f"❌ Falha ao bloquear porta {port}: {e}")
        except FileNotFoundError:
            self.logger.warning(f"⚠️ iptables não encontrado - Bloqueio simulado para porta {port}")
    
    def _register_blocked_port(self, port):
        self.blocked_ports[port] = {
            'blocked_at': time.time(),
            'reason': 'DDoS_Attack',
            'auto_unblock': self.config['blocking']['auto_unblock']
        }
    
    def _schedule_auto_unblock(self, port, duration):
        if self.config['blocking']['auto_unblock']:
            unblock_time = duration or self.auto_unblock_time
            Timer(unblock_time, self.unblock_port, args=[port]).start()
            self.logger.info(f"⏰ Auto-desbloqueio programado para porta {port} em {unblock_time}s")
    
    def _execute_iptables_block(self, port):
        subprocess.run([
            "iptables", "-A", "INPUT", "-p", "tcp",
            "--dport", str(port), "-j", "DROP"
        ], check=True)
    
    def unblock_port(self, port):
        if port not in self.blocked_ports:
            return
            
        self.logger.info(f"🔓 Desbloqueando porta {port}")
        
        try:
            self._execute_iptables_unblock(port)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.warning(f"⚠️ Falha ao desbloquear porta {port} ou iptables não disponível")
        
        del self.blocked_ports[port]
        self._notify_port_change(port, 'ACTIVE', 'Port unblocked')
        self.logger.info(f"✅ Porta {port} desbloqueada com sucesso")
    
    def _execute_iptables_unblock(self, port):
        subprocess.run([
            "iptables", "-D", "INPUT", "-p", "tcp",
            "--dport", str(port), "-j", "DROP"
        ], check=True)
    
    def is_whitelisted(self, ip_address):
        return ip_address in self.whitelist_ips
    
    def get_port_status(self):
        return {
            "blocked_ports": list(self.blocked_ports.keys()),
            "monitored_ports": list(self.config['detection']['ports'].keys()),
            "blocked_details": self.blocked_ports,
            "total_blocked": len(self.blocked_ports)
        }
