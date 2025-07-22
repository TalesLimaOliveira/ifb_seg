"""
Sistema Avançado de Detecção DDoS

Sistema integrado para detecção e mitigação de ataques DDoS em tempo real.
Monitora múltiplas portas, detecta padrões de ataque e aplica bloqueios automatizados.
"""

import logging
import sys
import time
from threading import Thread

from utils import load_configuration, setup_logging, validate_configuration, safe_log_message
from port_manager import PortManager
from multi_port_detector import MultiPortDetector
from notification_system import NotificationSystem
from multi_port_attacker import MultiPortAttacker


class DDoSDetectionSystem:
    """Sistema principal de detecção DDoS."""
    
    def __init__(self):
        self.config = None
        self.components = {}
        self.logger = None
        self.dashboard_thread = None
        self.detector_thread = None

    def initialize(self):
        """Inicializa todos os componentes do sistema."""
        print("🚀 INICIANDO SISTEMA AVANÇADO DE DETECÇÃO DDoS")
        print("=" * 60)
        
        if not self._load_and_validate_config():
            return False
        
        setup_logging()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self._initialize_components()
        self._initialize_dashboard()
        
        print("✅ Sistema inicializado com sucesso")
        return True

    def _load_and_validate_config(self):
        """Carrega e valida arquivo de configuração."""
        config_paths = ['config.yaml', '../config.yaml']
        
        for config_path in config_paths:
            self.config = load_configuration(config_path)
            if self.config:
                break
        
        if not self.config:
            print("❌ Falha ao carregar configurações")
            return False

        if not validate_configuration(self.config):
            print("❌ Configuração inválida")
            return False
        
        print("✅ Configurações validadas com sucesso")
        return True

    def _initialize_components(self):
        """Inicializa componentes principais do sistema."""
        self.components['port_manager'] = PortManager(self.config)
        self.components['notification_system'] = NotificationSystem(self.config)
        self.components['detector'] = MultiPortDetector(
            self.config,
            self.components['port_manager'],
            self.components['notification_system']
        )
        self.components['attacker'] = MultiPortAttacker(self.config)
        print("🔧 Componentes inicializados")

    def _initialize_dashboard(self):
        """Inicializa dashboard web se habilitado."""
        if not self.config['dashboard']['enabled']:
            print("📊 Dashboard desabilitado")
            return
        
        try:
            from dashboard import DashboardServer
            dashboard = DashboardServer(
                self.components['detector'],
                self.components['port_manager']
            )
            
            dashboard_port = self.config['dashboard'].get('port', 5000)
            
            def run_dashboard():
                dashboard.run(host='localhost', port=dashboard_port, debug=False)
            
            self.dashboard_thread = Thread(target=run_dashboard, daemon=True)
            self.dashboard_thread.start()
            print(f"🌐 Dashboard iniciado em http://localhost:{dashboard_port}")
            time.sleep(2)
        except ImportError as e:
            print(f"⚠️ Dashboard não disponível: {e}")
        except Exception as e:
            print(f"❌ Erro ao inicializar dashboard: {e}")

    def start_monitoring(self):
        """Inicia monitoramento de rede em thread separada."""
        self.detector_thread = Thread(
            target=self.components['detector'].start_monitoring,
            daemon=True
        )
        self.detector_thread.start()
        print("🔍 Monitoramento de rede iniciado")
        time.sleep(3)

    def run_attack_simulation(self, duration=120, intensity='high'):
        """Executa simulação de ataque DDoS."""
        self.logger.info(safe_log_message(f"💥 Iniciando simulação de ataque (duração: {duration}s)"))
        
        try:
            self.components['attacker'].run_simulation(
                duration=duration,
                attack_intensity=intensity
            )
        except KeyboardInterrupt:
            self.logger.info(safe_log_message("⏹️ Simulação interrompida pelo usuário"))

    def run_monitoring_mode(self):
        """Executa sistema em modo monitoramento contínuo."""
        print("🔄 Sistema em modo monitoramento. Pressione Ctrl+C para sair.")
        
        try:
            stats_counter = 0
            while True:
                time.sleep(10)
                stats_counter += 1
                
                if stats_counter >= 6:
                    stats = self.components['detector'].get_statistics()
                    if stats.get('active_attacks', 0) > 0 or stats.get('total_packets', 0) > 100:
                        print(f"📊 Atividade: {stats.get('total_packets', 0)} pacotes, {stats.get('active_attacks', 0)} ataques")
                    stats_counter = 0
                    
        except KeyboardInterrupt:
            print("🛑 Encerrando sistema...")

    def shutdown(self):
        """Finaliza sistema de forma limpa."""
        self.logger.info(safe_log_message("🔄 Finalizando sistema..."))
        print("\n" + "=" * 60)
        print("✅ SISTEMA FINALIZADO COM SUCESSO")


def main():
    """Função principal da aplicação."""
    print("🚀 INICIANDO SISTEMA AVANÇADO DE DETECÇÃO DDoS")
    print("=" * 60)
    
    system = DDoSDetectionSystem()
    
    if not system.initialize():
        print("❌ Falha na inicialização do sistema")
        return 1
    
    try:
        system.start_monitoring()
        
        dashboard_port = system.config['dashboard'].get('port', 5000)
        print(f"🌐 Dashboard disponível em: http://localhost:{dashboard_port}")
        print("🔍 Sistema de detecção ativo")
        print("💡 Pressione Ctrl+C para encerrar o sistema")
        print("=" * 60)
        
        system.run_monitoring_mode()
        
    except Exception as e:
        system.logger.error(f"❌ Erro crítico: {e}")
        return 1
    finally:
        system.shutdown()
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
"""
Sistema Avançado de Detecção DDoS

Sistema integrado para detecção e mitigação de ataques DDoS em tempo real.
Monitora múltiplas portas, detecta padrões de ataque e aplica bloqueios automatizados.
"""

import logging
import sys
import time
from threading import Thread

from utils import load_configuration, setup_logging, validate_configuration, safe_log_message
from port_manager import PortManager
from multi_port_detector import MultiPortDetector
from notification_system import NotificationSystem
from multi_port_attacker import MultiPortAttacker


class DDoSDetectionSystem:
    """Sistema principal de detecção DDoS."""
    
    def __init__(self):
        self.config = None
        self.components = {}
        self.logger = None
        self.dashboard_thread = None
        self.detector_thread = None

    def initialize(self):
        """Inicializa todos os componentes do sistema."""
        print("🚀 INICIANDO SISTEMA AVANÇADO DE DETECÇÃO DDoS")
        print("=" * 60)
        
        if not self._load_and_validate_config():
            return False
        
        setup_logging()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self._initialize_components()
        self._initialize_dashboard()
        
        print("✅ Sistema inicializado com sucesso")
        return True

    def _load_and_validate_config(self):
        """Carrega e valida arquivo de configuração."""
        config_paths = ['config.yaml', '../config.yaml']
        
        for config_path in config_paths:
            self.config = load_configuration(config_path)
            if self.config:
                break
        
        if not self.config:
            print("❌ Falha ao carregar configurações")
            return False

        if not validate_configuration(self.config):
            print("❌ Configuração inválida")
            return False
        
        print("✅ Configurações validadas com sucesso")
        return True

    def _initialize_components(self):
        """Inicializa componentes principais do sistema."""
        self.components['port_manager'] = PortManager(self.config)
        self.components['notification_system'] = NotificationSystem(self.config)
        self.components['detector'] = MultiPortDetector(
            self.config,
            self.components['port_manager'],
            self.components['notification_system']
        )
        self.components['attacker'] = MultiPortAttacker(self.config)
        print("🔧 Componentes inicializados")

    def _initialize_dashboard(self):
        """Inicializa dashboard web se habilitado."""
        if not self.config['dashboard']['enabled']:
            print("📊 Dashboard desabilitado")
            return
        
        try:
            from dashboard import DashboardServer
            dashboard = DashboardServer(
                self.components['detector'],
                self.components['port_manager']
            )
            
            dashboard_port = self.config['dashboard'].get('port', 5000)
            
            def run_dashboard():
                dashboard.run(host='localhost', port=dashboard_port, debug=False)
            
            self.dashboard_thread = Thread(target=run_dashboard, daemon=True)
            self.dashboard_thread.start()
            print(f"🌐 Dashboard iniciado em http://localhost:{dashboard_port}")
            time.sleep(2)
        except ImportError as e:
            print(f"⚠️ Dashboard não disponível: {e}")
        except Exception as e:
            print(f"❌ Erro ao inicializar dashboard: {e}")

    def start_monitoring(self):
        """Inicia monitoramento de rede em thread separada."""
        self.detector_thread = Thread(
            target=self.components['detector'].start_monitoring,
            daemon=True
        )
        self.detector_thread.start()
        print("🔍 Monitoramento de rede iniciado")
        time.sleep(3)

    def run_attack_simulation(self, duration=120, intensity='high'):
        """Executa simulação de ataque DDoS."""
        self.logger.info(safe_log_message(f"💥 Iniciando simulação de ataque (duração: {duration}s)"))
        
        try:
            self.components['attacker'].run_simulation(
                duration=duration,
                attack_intensity=intensity
            )
        except KeyboardInterrupt:
            self.logger.info(safe_log_message("⏹️ Simulação interrompida pelo usuário"))

    def run_monitoring_mode(self):
        """Executa sistema em modo monitoramento contínuo."""
        print("🔄 Sistema em modo monitoramento. Pressione Ctrl+C para sair.")
        
        try:
            stats_counter = 0
            while True:
                time.sleep(10)
                stats_counter += 1
                
                if stats_counter >= 6:
                    stats = self.components['detector'].get_statistics()
                    if stats.get('active_attacks', 0) > 0 or stats.get('total_packets', 0) > 100:
                        print(f"📊 Atividade: {stats.get('total_packets', 0)} pacotes, {stats.get('active_attacks', 0)} ataques")
                    stats_counter = 0
                    
        except KeyboardInterrupt:
            print("🛑 Encerrando sistema...")

    def shutdown(self):
        """Finaliza sistema de forma limpa."""
        self.logger.info(safe_log_message("🔄 Finalizando sistema..."))
        print("\n" + "=" * 60)
        print("✅ SISTEMA FINALIZADO COM SUCESSO")


def main():
    """Função principal da aplicação."""
    print("🚀 INICIANDO SISTEMA AVANÇADO DE DETECÇÃO DDoS")
    print("=" * 60)
    
    system = DDoSDetectionSystem()
    
    if not system.initialize():
        print("❌ Falha na inicialização do sistema")
        return 1
    
    try:
        system.start_monitoring()
        
        dashboard_port = system.config['dashboard'].get('port', 5000)
        print(f"🌐 Dashboard disponível em: http://localhost:{dashboard_port}")
        print("🔍 Sistema de detecção ativo")
        print("💡 Pressione Ctrl+C para encerrar o sistema")
        print("=" * 60)
        
        system.run_monitoring_mode()
        
    except Exception as e:
        system.logger.error(f"❌ Erro crítico: {e}")
        return 1
    finally:
        system.shutdown()
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
