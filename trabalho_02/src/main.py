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

import logging
import time
import sys
import os
from threading import Thread

# Importa componentes do sistema
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
        """
        Inicializa o sistema de detecção DDoS.
        
        Prepara todas as estruturas necessárias mas não inicia os componentes.
        A inicialização real acontece no método initialize().
        """
        self.config = None
        self.components = {}
        self.logger = None
        self.dashboard_thread = None
        self.detector_thread = None
    
    def initialize(self):
        """
        Inicializa todos os componentes do sistema de detecção DDoS.
        
        Executa uma sequência ordenada de inicialização:
        1. Carrega e valida configurações do arquivo YAML
        2. Configura sistema de logging centralizado
        3. Inicializa componentes principais (detector, port manager, notificações)
        4. Inicia dashboard web se habilitado
        
        Returns:
            bool: True se inicialização foi bem-sucedida, False caso contrário
            
        Raises:
            Exception: Se houver falha crítica na inicialização
        """
        print("🚀 INICIANDO SISTEMA AVANÇADO DE DETECÇÃO DDoS")
        print("=" * 60)
        
        # Carrega e valida configurações
        if not self._load_and_validate_config():
            return False
        
        # Configura sistema de logging
        setup_logging()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Inicializa componentes principais
        self._initialize_components()
        
        # Inicializa dashboard se habilitado
        self._initialize_dashboard()
        
        print("✅ Sistema inicializado com sucesso")
        return True
    
    def _load_and_validate_config(self):
        """
        Carrega e valida arquivo de configuração YAML.
        
        Tenta carregar o arquivo config.yaml do diretório atual e do diretório pai.
        Valida se todas as configurações necessárias estão presentes e corretas.
        
        Returns:
            bool: True se configuração foi carregada e validada com sucesso
        """
        # Tenta carregar config.yaml do diretório atual e do diretório pai
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
        """
        Inicializa todos os componentes principais do sistema.
        
        Cria instâncias dos componentes principais na ordem correta:
        1. PortManager: Gerencia bloqueio/desbloqueio de portas via iptables
        2. NotificationSystem: Sistema de alertas multi-canal
        3. MultiPortDetector: Detector principal de ataques DDoS
        4. MultiPortAttacker: Simulador de ataques para testes
        
        Os componentes são interconectados através de callbacks e referências.
        """
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
        """
        Inicializa dashboard web se habilitado na configuração.
        
        O dashboard fornece interface web em tempo real para:
        - Monitoramento de ataques detectados
        - Controle manual de portas
        - Visualização de logs e estatísticas
        - Simulação de ataques
        
        Executa em thread separada para não bloquear o sistema principal.
        
        Raises:
            ImportError: Se módulo dashboard não estiver disponível
            Exception: Se houver erro na inicialização do servidor web
        """
        if not self.config['dashboard']['enabled']:
            print("📊 Dashboard desabilitado")
            return
        
        try:
            from dashboard import DashboardServer
            dashboard = DashboardServer(
                self.components['detector'],
                self.components['port_manager']
            )
            
            # Configura argumentos do dashboard
            dashboard_port = self.config['dashboard'].get('port', 5000)
            
            def run_dashboard():
                dashboard.run(host='localhost', port=dashboard_port, debug=False)
            
            self.dashboard_thread = Thread(target=run_dashboard, daemon=True)
            self.dashboard_thread.start()
            print(f"🌐 Dashboard iniciado em http://localhost:{dashboard_port}")
            time.sleep(2)  # Aguarda dashboard inicializar
        except ImportError as e:
            print(f"⚠️ Dashboard não disponível: {e}")
        except Exception as e:
            print(f"❌ Erro ao inicializar dashboard: {e}")
    
    def start_monitoring(self):
        """
        Inicia o monitoramento de rede em thread separada.
        
        Cria e inicia uma thread daemon para executar o detector de ataques.
        A thread daemon garante que o programa possa encerrar cleanamente
        mesmo se o monitoramento estiver ativo.
        
        O detector fica em loop contínuo analisando pacotes de rede
        e detectando padrões de ataques DDoS.
        """
        self.detector_thread = Thread(
            target=self.components['detector'].start_monitoring,
            daemon=True
        )
        self.detector_thread.start()
        print("🔍 Monitoramento de rede iniciado")
        time.sleep(3)  # Aguarda detector estar pronto
    
    def run_attack_simulation(self, duration=120, intensity='high'):
        """
        Executa simulação de ataque DDoS para testes do sistema.
        
        Utiliza o componente MultiPortAttacker para gerar tráfego
        simulado que imita padrões de ataques DDoS reais. Útil para:
        - Validar detecção de ataques
        - Testar resposta do sistema
        - Demonstrar funcionalidades
        - Treinar operadores
        
        Args:
            duration (int): Duração da simulação em segundos (padrão: 120)
            intensity (str): Intensidade do ataque - 'low', 'medium', 'high' (padrão: 'high')
            
        Raises:
            KeyboardInterrupt: Se usuário interromper a simulação
            Exception: Se houver erro na execução da simulação
        """
        self.logger.info(safe_log_message(f"💥 Iniciando simulação de ataque (duração: {duration}s)"))
        
        try:
            self.components['attacker'].run_simulation(
                duration=duration,
                attack_intensity=intensity
            )
        except KeyboardInterrupt:
            self.logger.info(safe_log_message("⏹️ Simulação interrompida pelo usuário"))
    
    def run_monitoring_mode(self):
        """
        Executa sistema em modo monitoramento contínuo.
        
        Mantém o sistema principal em execução, exibindo estatísticas
        periodicamente. O loop principal:
        - Aguarda 10 segundos entre verificações
        - Exibe estatísticas a cada 60 segundos (6 ciclos)
        - Mostra apenas atividade relevante (ataques ou tráfego alto)
        - Pode ser interrompido com Ctrl+C
        
        Este é o modo padrão de operação do sistema.
        
        Raises:
            KeyboardInterrupt: Quando usuário pressiona Ctrl+C para encerrar
        """
        print("🔄 Sistema em modo monitoramento. Pressione Ctrl+C para sair.")
        
        try:
            stats_counter = 0
            while True:
                time.sleep(10)
                stats_counter += 1
                
                # Exibe estatísticas apenas a cada 60 segundos (6 ciclos)
                if stats_counter >= 6:
                    stats = self.components['detector'].get_statistics()
                    if stats.get('active_attacks', 0) > 0 or stats.get('total_packets', 0) > 100:
                        print(f"📊 Atividade: {stats.get('total_packets', 0)} pacotes, {stats.get('active_attacks', 0)} ataques")
                    stats_counter = 0
                    
        except KeyboardInterrupt:
            print("🛑 Encerrando sistema...")
    
    def shutdown(self):
        """
        Finaliza o sistema de forma limpa e controlada.
        
        Executa procedimentos de limpeza e finalização:
        - Registra evento de finalização no log
        - Permite extensão futura para limpeza de recursos
        - Exibe mensagem de confirmação de encerramento
        
        Este método é chamado automaticamente no bloco finally
        da função main para garantir finalização limpa mesmo
        em caso de exceções.
        """
        self.logger.info(safe_log_message("🔄 Finalizando sistema..."))
        # Aqui poderia implementar limpeza adicional se necessário
        print("\n" + "=" * 60)
        print("✅ SISTEMA FINALIZADO COM SUCESSO")


def main():
    """
    Função principal da aplicação - ponto de entrada do sistema.
    
    Coordena a execução completa do sistema de detecção DDoS:
    1. Inicializa o sistema e todos seus componentes
    2. Inicia monitoramento de rede em background
    3. Ativa dashboard web para interface do usuário
    4. Mantém sistema em execução contínua
    5. Garante finalização limpa em caso de erro ou interrupção
    
    Returns:
        int: Código de saída (0 = sucesso, 1 = erro)
        
    Raises:
        Exception: Captura e trata qualquer erro crítico do sistema
    """
    print("🚀 INICIANDO SISTEMA AVANÇADO DE DETECÇÃO DDoS")
    print("=" * 60)
    
    # Inicializa sistema
    system = DDosDetectionSystem()
    
    if not system.initialize():
        print("❌ Falha na inicialização do sistema")
        return 1
    
    try:
        # Inicia monitoramento em thread separada
        system.start_monitoring()
        
        # Exibe informações do sistema
        dashboard_port = system.config['dashboard'].get('port', 5000)
        print(f"🌐 Dashboard disponível em: http://localhost:{dashboard_port}")
        print("🔍 Sistema de detecção ativo")
        print("💡 Pressione Ctrl+C para encerrar o sistema")
        print("=" * 60)
        
        # Mantém o sistema rodando
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
