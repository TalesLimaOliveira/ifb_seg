"""
Gerenciador de Portas para Sistema de Detecção DDoS

Este módulo implementa o gerenciamento inteligente de portas de rede,
incluindo bloqueio/desbloqueio automático e controle de whitelist de IPs.

Classes:
    PortManager: Gerenciador principal de controle de portas

Funcionalidades:
    - Bloqueio automático de portas específicas
    - Desbloqueio programado com timer configurável  
    - Gerenciamento de whitelist de IPs confiáveis
    - Logging estruturado de todas as ações

Author: Sistema de Detecção DDoS - IFB
"""

import time
import logging
import subprocess
import os
from threading import Timer
from datetime import datetime


class PortManager:
    """
    Gerenciador inteligente de portas para sistema de detecção DDoS.
    
    Esta classe implementa o controle granular de bloqueio/desbloqueio de portas
    específicas, permitindo que apenas portas sob ataque sejam bloqueadas,
    mantendo o resto do sistema funcionando normalmente.
    
    Attributes:
        config (dict): Configurações do sistema
        blocked_ports (dict): Dicionário de portas bloqueadas com metadados
        auto_unblock_time (int): Tempo em segundos para desbloqueio automático
        whitelist_ips (list): Lista de IPs que nunca são bloqueados
        port_change_callbacks (list): Callbacks para mudanças de status
    """
    
    def __init__(self, config):
        """
        Inicializa o gerenciador de portas.
        
        Args:
            config (dict): Configurações carregadas do arquivo config.yaml
                Deve conter as chaves 'blocking' com 'unblock_time' e 'whitelist_ips'
        """
        self.config = config
        self.blocked_ports = {}  # Dicionário: {porta: {blocked_at, reason}}
        self.auto_unblock_time = config['blocking']['unblock_time']
        self.whitelist_ips = config['blocking']['whitelist_ips']
        self.port_change_callbacks = []  # Lista de callbacks para mudanças de status
        
        # Configurar sistema de logging estruturado
        self._setup_logging()
    
    def _setup_logging(self):
        """
        Configura sistema de logging estruturado para o gerenciador de portas.
        
        Cria logs tanto em arquivo quanto no console para monitoramento
        de ações de bloqueio e desbloqueio de portas.
        """
        import os
        
        # Criar diretório de logs se não existir
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, 'port_manager.log')),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def add_port_change_callback(self, callback):
        """
        Adiciona função callback para ser notificada sobre mudanças de status de portas.
        
        Args:
            callback (callable): Função que será chamada com parâmetros (port, status, reason)
                - port (int): Número da porta afetada
                - status (str): Novo status ('BLOCKED' ou 'ACTIVE')  
                - reason (str): Descrição da razão da mudança
        """
        self.port_change_callbacks.append(callback)
    
    def _notify_port_change(self, port, status, reason=""):
        """
        Notifica todos os callbacks sobre mudança de status de porta.
        
        Args:
            port (int): Número da porta
            status (str): Novo status ('BLOCKED' ou 'ACTIVE')
            reason (str): Razão da mudança
        """
        for callback in self.port_change_callbacks:
            try:
                callback(port, status, reason)
            except Exception as e:
                self.logger.error(f"Erro em callback de porta: {e}")
    
    def block_port(self, port, duration=None):
        """
        Bloqueia uma porta específica usando regras de firewall.
        
        Implementa bloqueio granular que afeta apenas a porta especificada,
        mantendo outras portas funcionando normalmente. Se o desbloqueio
        automático estiver habilitado, programa um timer para desbloqueio.
        
        Args:
            port (int): Número da porta a ser bloqueada (ex: 80, 443, 22)
            duration (int, optional): Duração personalizada do bloqueio em segundos.
                Se não especificado, usa o tempo padrão do config.
                
        Note:
            - Apenas bloqueia se a porta não estiver já bloqueada
            - Registra a ação no log do sistema
            - Notifica callbacks registrados sobre a mudança
            - Em sistemas sem iptables, simula o bloqueio
        """
        if port not in self.blocked_ports:
            self.logger.warning(f"🔒 BLOQUEANDO PORTA {port} - Ataque DDoS detectado!")
            
            try:
                # Executa comando iptables para bloquear porta específica
                self._execute_iptables_block(port)
                
                # Registra informações do bloqueio
                self.blocked_ports[port] = {
                    'blocked_at': time.time(),
                    'reason': 'DDoS_Attack',
                    'auto_unblock': self.config['blocking']['auto_unblock']
                }
                
                # Notifica mudança de status
                self._notify_port_change(port, 'BLOCKED', 'DDoS Attack detected')
                
                # Programa desbloqueio automático se habilitado
                if self.config['blocking']['auto_unblock']:
                    unblock_time = duration or self.auto_unblock_time
                    Timer(unblock_time, self.unblock_port, args=[port]).start()
                    self.logger.info(f"⏰ Auto-desbloqueio programado para porta {port} em {unblock_time}s")
                          
            except subprocess.CalledProcessError as e:
                self.logger.error(f"❌ Falha ao bloquear porta {port}: {e}")
            except FileNotFoundError:
                self.logger.warning(f"⚠️ iptables não encontrado - Bloqueio simulado para porta {port}")
    
    def _execute_iptables_block(self, port):
        """
        Executa comando iptables para bloqueio.
        
        Args:
            port (int): Porta a ser bloqueada
        """
        subprocess.run([
            "iptables", "-A", "INPUT", "-p", "tcp",
            "--dport", str(port), "-j", "DROP"
        ], check=True)
    
    def unblock_port(self, port):
        """
        Remove o bloqueio de uma porta específica.
        
        Remove a regra de firewall que estava bloqueando a porta,
        restaurando o acesso normal à mesma.
        
        Args:
            port (int): Número da porta a ser desbloqueada
            
        Note:
            - Apenas tenta desbloquear se a porta estiver bloqueada
            - Remove a porta da lista de portas bloqueadas
            - Notifica callbacks sobre a mudança de status
            - Em caso de erro, registra no log mas continua o processo
        """
        if port in self.blocked_ports:
            self.logger.info(f"🔓 Desbloqueando porta {port}")
            
            try:
                # Remove regra específica do iptables
                self._execute_iptables_unblock(port)
                
            except (subprocess.CalledProcessError, FileNotFoundError):
                self.logger.warning(f"⚠️ Falha ao desbloquear porta {port} ou iptables não disponível")
            
            # Remove da lista de portas bloqueadas
            del self.blocked_ports[port]
            
            # Notifica mudança de status
            self._notify_port_change(port, 'ACTIVE', 'Port unblocked')
            
            self.logger.info(f"✅ Porta {port} desbloqueada com sucesso")
    
    def _execute_iptables_unblock(self, port):
        """
        Executa comando iptables para desbloqueio.
        
        Args:
            port (int): Porta a ser desbloqueada
        """
        subprocess.run([
            "iptables", "-D", "INPUT", "-p", "tcp",
            "--dport", str(port), "-j", "DROP"
        ], check=True)
    
    def is_whitelisted(self, ip_address):
        """
        Verifica se um IP está na lista de IPs confiáveis.
        
        Args:
            ip_address (str): Endereço IP a ser verificado
            
        Returns:
            bool: True se o IP está na whitelist, False caso contrário
        """
        return ip_address in self.whitelist_ips
    
    def get_port_status(self):
        """
        Retorna status detalhado de todas as portas monitoradas.
        
        Returns:
            dict: Dicionário com informações sobre portas bloqueadas,
                  monitoradas e detalhes dos bloqueios
        """
        return {
            "blocked_ports": list(self.blocked_ports.keys()),
            "monitored_ports": list(self.config['detection']['ports'].keys()),
            "blocked_details": self.blocked_ports,
            "total_blocked": len(self.blocked_ports)
        }
