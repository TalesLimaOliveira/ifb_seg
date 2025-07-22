"""
Sistema Avançado de Detecção DDoS - Ponto de Entrada Principal

Este módulo contém a classe principal que orquestra todo o sistema de detecção DDoS,
coordenando a inicialização, execução e finalização de todos os componentes:
- Detector de ataques multi-porta
- Gerenciador de portas com iptables
- Sistema de notificações
- Dashboard web em tempo real
- Simulador de ataques para testes

Autor: Sistema de Segurança IFB
Data: 2024
"""

# Importações das bibliotecas padrão
import logging        # Para logs do sistema
import time          # Para controle de tempo e delays
import sys           # Para argumentos do sistema e exit codes
import os            # Para operações do sistema operacional
from threading import Thread  # Para execução paralela

# Importa todos os componentes do sistema
from utils import load_configuration, setup_logging, validate_configuration, safe_log_message
from port_manager import PortManager
from multi_port_detector import MultiPortDetector
from notification_system import NotificationSystem
from multi_port_attacker import MultiPortAttacker


class DDosDetectionSystem:
    """
    Classe principal que coordena todo o sistema de detecção DDoS.
    
    Esta classe atua como um orquestrador central, gerenciando:
    - Inicialização e configuração de todos os componentes
    - Coordenação entre detector, gerenciador de portas e notificações
    - Execução do dashboard web em tempo real
    - Simulação de ataques para testes e validação
    - Monitoramento contínuo e relatórios de estatísticas
    - Finalização limpa do sistema
    
    Attributes:
        config (dict): Configurações carregadas do arquivo YAML
        components (dict): Dicionário com todos os componentes do sistema
        logger (logging.Logger): Logger principal do sistema
        dashboard_thread (Thread): Thread do servidor web dashboard
        detector_thread (Thread): Thread do detector de ataques
    """
    
    def __init__(self):
        # Configurações do sistema (carregadas do YAML)
        self.config = None
        # Dicionário que armazena todos os componentes do sistema
        self.components = {}
        # Logger principal do sistema
        self.logger = None
        # Thread do dashboard web
        self.dashboard_thread = None
        # Thread do detector de ataques
        self.detector_thread = None
    

    def initialize(self):
        print("🚀 INICIANDO SISTEMA AVANÇADO DE DETECÇÃO DDoS")
        print("=" * 60)
        
        # Primeiro passo: carrega e valida configurações
        if not self._load_and_validate_config():
            return False
        
        # Segundo passo: configura sistema de logging
        setup_logging()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Terceiro passo: inicializa todos os componentes
        self._initialize_components()
        
        # Quarto passo: inicia dashboard se habilitado
        self._initialize_dashboard()
        
        print("✅ Sistema inicializado com sucesso")
        return True
    

    def _load_and_validate_config(self):
        # Lista de caminhos onde procurar o arquivo de configuração
        config_paths = ['config.yaml', '../config.yaml']
        
        # Tenta carregar config de cada caminho até encontrar
        for config_path in config_paths:
            self.config = load_configuration(config_path)
            if self.config:
                break
        
        # Verifica se conseguiu carregar alguma configuração
        if not self.config:
            print("❌ Falha ao carregar configurações")
            return False

        # Valida se a configuração está correta
        if not validate_configuration(self.config):
            print("❌ Configuração inválida")
            return False
        
        print("✅ Configurações validadas com sucesso")
        return True
    

    def _initialize_components(self):
        # Inicializa componentes na ordem correta de dependências
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
        # Verifica se dashboard está habilitado na configuração
        if not self.config['dashboard']['enabled']:
            print("📊 Dashboard desabilitado")
            return
        
        try:
            # Importa e configura servidor do dashboard
            from dashboard import DashboardServer
            dashboard = DashboardServer(
                self.components['detector'],
                self.components['port_manager']
            )
            
            # Pega porta configurada ou usa padrão 5000
            dashboard_port = self.config['dashboard'].get('port', 5000)
            
            # Função para executar dashboard em thread separada
            def run_dashboard():
                dashboard.run(host='localhost', port=dashboard_port, debug=False)
            
            # Inicia dashboard em thread daemon
            self.dashboard_thread = Thread(target=run_dashboard, daemon=True)
            self.dashboard_thread.start()
            print(f"🌐 Dashboard iniciado em http://localhost:{dashboard_port}")
            time.sleep(2)  # Aguarda dashboard estar pronto
        except ImportError as e:
            print(f"⚠️ Dashboard não disponível: {e}")
        except Exception as e:
            print(f"❌ Erro ao inicializar dashboard: {e}")
    

    def start_monitoring(self):
        # Cria thread daemon para executar o detector
        self.detector_thread = Thread(
            target=self.components['detector'].start_monitoring,
            daemon=True  # Thread daemon encerra quando programa principal encerra
        )
        # Inicia a thread de monitoramento
        self.detector_thread.start()
        print("🔍 Monitoramento de rede iniciado")
        time.sleep(3)  # Aguarda detector estar pronto
    
    
    def run_attack_simulation(self, duration=120, intensity='high'):
        # Log de início da simulação
        self.logger.info(safe_log_message(f"💥 Iniciando simulação de ataque (duração: {duration}s)"))
        
        try:
            # Executa a simulação com parâmetros especificados
            self.components['attacker'].run_simulation(
                duration=duration,
                attack_intensity=intensity
            )
        except KeyboardInterrupt:
            # Trata interrupção pelo usuário
            self.logger.info(safe_log_message("⏹️ Simulação interrompida pelo usuário"))
    

    def run_monitoring_mode(self):
        print("🔄 Sistema em modo monitoramento. Pressione Ctrl+C para sair.")
        
        try:
            # Contador para controlar exibição de estatísticas
            stats_counter = 0
            while True:
                # Aguarda 10 segundos entre verificações
                time.sleep(10)
                stats_counter += 1
                
                # Exibe estatísticas a cada 60 segundos (6 ciclos de 10s)
                if stats_counter >= 6:
                    # Busca estatísticas atuais do detector
                    stats = self.components['detector'].get_statistics()
                    # Só mostra se há atividade relevante
                    if stats.get('active_attacks', 0) > 0 or stats.get('total_packets', 0) > 100:
                        print(f"📊 Atividade: {stats.get('total_packets', 0)} pacotes, {stats.get('active_attacks', 0)} ataques")
                    stats_counter = 0  # Reseta contador
                    
        except KeyboardInterrupt:
            # Trata Ctrl+C do usuário
            print("🛑 Encerrando sistema...")
    
    def shutdown(self):
        # Registra no log que o sistema está sendo finalizado
        self.logger.info(safe_log_message("🔄 Finalizando sistema..."))
        # Local para futuras limpezas de recursos se necessário
        # (como fechar conexões, parar threads, etc.)
        print("\n" + "=" * 60)
        print("✅ SISTEMA FINALIZADO COM SUCESSO")


def main():
    print("🚀 INICIANDO SISTEMA AVANÇADO DE DETECÇÃO DDoS")
    print("=" * 60)
    
    # Cria instância do sistema principal
    system = DDosDetectionSystem()
    
    # Tenta inicializar todos os componentes
    if not system.initialize():
        print("❌ Falha na inicialização do sistema")
        return 1
    
    try:
        # Inicia monitoramento de rede em thread separada
        system.start_monitoring()
        
        # Exibe informações importantes para o usuário
        dashboard_port = system.config['dashboard'].get('port', 5000)
        print(f"🌐 Dashboard disponível em: http://localhost:{dashboard_port}")
        print("🔍 Sistema de detecção ativo")
        print("💡 Pressione Ctrl+C para encerrar o sistema")
        print("=" * 60)
        
        # Entra em modo monitoramento contínuo
        system.run_monitoring_mode()
        
    except Exception as e:
        # Trata qualquer erro crítico que possa ocorrer
        system.logger.error(f"❌ Erro crítico: {e}")
        return 1
    finally:
        # Sempre executa limpeza, mesmo em caso de erro
        system.shutdown()
    
    return 0  # Código de sucesso


if __name__ == "__main__":
    # Executa função principal e sai com código retornado
    exit_code = main()
    sys.exit(exit_code)
