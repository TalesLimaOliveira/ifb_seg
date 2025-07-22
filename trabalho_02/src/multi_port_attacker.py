"""
Simulador de Ataques DDoS Multi-Porta

Este módulo implementa um simulador realístico de ataques DDoS que:
- Simula ataques direcionados a portas específicas
- Gera tráfego normal em outras portas para realismo
- Suporta diferentes intensidades de ataque (low, medium, high)
- Executa múltiplas threads para simular cenários reais
- Fornece estatísticas detalhadas da simulação

O simulador é usado para:
- Testar eficácia do sistema de detecção
- Demonstrar funcionamento em tempo real
- Validar respostas automáticas do sistema
- Treinar operadores de segurança

Autor: Sistema de Segurança IFB
Data: 2024
"""

import time
import random
import threading
import logging
from datetime import datetime


class MultiPortAttacker:
    """
    Simulador avançado de ataques DDoS em múltiplas portas.
    
    Esta classe simula cenários realísticos de ataques DDoS onde:
    - Uma porta é selecionada como alvo principal do ataque
    - Outras portas mantêm tráfego normal para realismo
    - Diferentes intensidades de ataque podem ser configuradas
    - Estatísticas detalhadas são coletadas durante a simulação
    
    O simulador utiliza threading para executar múltiplos tipos de
    tráfego simultaneamente, criando um ambiente de teste realístico.
    
    Attributes:
        config (dict): Configurações do sistema carregadas do YAML
        monitored_ports (list): Lista de portas configuradas para monitoramento
        attack_port (int): Porta atualmente selecionada para ataque
        logger (logging.Logger): Logger para registrar eventos de simulação
        attack_stats (dict): Estatísticas da simulação em andamento
    """
    
    def __init__(self, config):
        """
        Inicializa o simulador de ataques DDoS.
        
        Args:
            config (dict): Configurações do sistema contendo:
                - detection.ports: Dicionário de portas monitoras
                - Configurações de thresholds e detecção
                
        Raises:
            KeyError: Se configurações necessárias não estiverem presentes
        """
        self.config = config
        self.monitored_ports = list(config['detection']['ports'].keys())
        self.attack_port = None
        self.logger = logging.getLogger(__name__)
        
        # Estatísticas detalhadas da simulação
        self.attack_stats = {
            'start_time': None,
            'packets_sent': 0,
            'target_port': None,
            'normal_traffic_ports': []
        }
    
    def select_attack_port(self):
        """
        Seleciona aleatoriamente uma porta para ser o alvo do ataque.
        
        Escolhe uma porta dentre as configuradas para monitoramento
        e registra a seleção nas estatísticas da simulação.
        
        Returns:
            int: Número da porta selecionada para ataque
            
        Side Effects:
            - Atualiza self.attack_port com a porta selecionada
            - Registra seleção no log e estatísticas
        """
        self.attack_port = random.choice(self.monitored_ports)
        self.attack_stats['target_port'] = self.attack_port
        
        port_info = self.config['detection']['ports'][self.attack_port]
        self.logger.info(
            f"🎯 PORTA SELECIONADA PARA ATAQUE: {self.attack_port} "
            f"({port_info['protocol']} - {port_info['description']})"
        )
        
        return self.attack_port
    
    def simulate_normal_traffic(self, port, duration=60):
        """
        Simula tráfego normal e legítimo em uma porta específica.
        
        Gera padrão de tráfego que imita uso normal de serviços:
        - Intervalos aleatórios entre requisições (1-5 segundos)
        - Volume baixo e constante de pacotes
        - Sem rajadas ou picos anômalos
        
        Este tráfego serve como "ruído de fundo" realístico durante
        a simulação de ataques, ajudando a validar que o detector
        consegue distinguir entre tráfego normal e malicioso.
        
        Args:
            port (int): Porta para simular tráfego normal
            duration (int): Duração da simulação em segundos (padrão: 60)
            
        Side Effects:
            - Gera logs de debug a cada 10 pacotes
            - Atualiza estatísticas internas de tráfego
        """
        port_info = self.config['detection']['ports'][port]
        self.logger.info(f"✅ Iniciando tráfego normal na porta {port} ({port_info['protocol']})")
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            # Intervalo aleatório entre requisições normais (1-5 segundos)
            time.sleep(random.uniform(1, 5))
            
            # Simula requisição normal
            packet_count += 1
            if packet_count % 10 == 0:
                self.logger.debug(f"✅ Tráfego normal na porta {port}: {packet_count} pacotes")
        
        self.logger.info(f"✅ Tráfego normal finalizado na porta {port}: {packet_count} pacotes")
    
    def simulate_ddos_attack(self, port, duration=60, intensity='high'):
        """
        Simula ataque DDoS direcionado a uma porta específica.
        
        Gera padrão de tráfego malicioso característico de ataques DDoS:
        - Alto volume de pacotes em rajadas
        - Taxa muito superior aos limites normais
        - Intervalos curtos entre pacotes
        - Volume que excede thresholds configurados
        
        Intensidades disponíveis:
        - 'low': 10 pps, excede threshold em ~20 pacotes
        - 'medium': 20 pps, excede threshold em ~50 pacotes  
        - 'high': 100 pps, excede threshold em ~100 pacotes
        
        Args:
            port (int): Porta alvo do ataque
            duration (int): Duração do ataque em segundos (padrão: 60)
            intensity (str): Intensidade - 'low', 'medium', 'high' (padrão: 'high')
            
        Side Effects:
            - Atualiza estatísticas de ataque em tempo real
            - Gera logs de warning durante execução
            - Calcula e exibe taxa de pacotes por segundo
        """
        port_info = self.config['detection']['ports'][port]
        max_requests = port_info['max_requests']
        
        # Define intensidade do ataque baseada no threshold da porta
        if intensity == 'low':
            interval = 0.1  # 10 pacotes por segundo
            burst_size = max_requests + 20
        elif intensity == 'medium':
            interval = 0.05  # 20 pacotes por segundo
            burst_size = max_requests + 50
        else:  # high
            interval = 0.01  # 100 pacotes por segundo
            burst_size = max_requests + 100
        
        self.logger.warning(
            f"💥 INICIANDO ATAQUE DDoS na porta {port} "
            f"({port_info['protocol']}) - Intensidade: {intensity.upper()}"
        )
        
        start_time = time.time()
        self.attack_stats['start_time'] = start_time
        packet_count = 0
        
        while time.time() - start_time < duration:
            # Envia rajada de pacotes
            for _ in range(burst_size):
                time.sleep(interval)
                packet_count += 1
                self.attack_stats['packets_sent'] = packet_count
                
                # Log a cada 100 pacotes para acompanhar progresso
                if packet_count % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = packet_count / elapsed
                    self.logger.warning(
                        f"🔥 Ataque em andamento na porta {port}: "
                        f"{packet_count} pacotes ({rate:.1f} pps)"
                    )
            
            # Pausa curta entre rajadas para simular comportamento real
            time.sleep(random.uniform(0.5, 2))
        
        self.logger.warning(
            f"💥 ATAQUE FINALIZADO na porta {port}: "
            f"{packet_count} pacotes enviados em {duration}s"
        )
    
    def run_simulation(self, duration=120, attack_intensity='high'):
        """
        Executa simulação completa de ataque multi-porta.
        
        Coordena uma simulação realística onde:
        1. Uma porta é selecionada aleatoriamente para ataque DDoS
        2. Todas as outras portas mantêm tráfego normal
        3. Múltiplas threads executam simultaneamente
        4. Estatísticas são coletadas durante toda execução
        5. Resumo detalhado é exibido ao final
        
        Esta simulação permite testar:
        - Capacidade de detecção do sistema
        - Precisão na identificação de portas atacadas
        - Comportamento com tráfego misto (normal + malicioso)
        - Performance sob carga de múltiplas threads
        
        Args:
            duration (int): Duração total da simulação em segundos (padrão: 120)
            attack_intensity (str): Intensidade do ataque - 'low'/'medium'/'high' (padrão: 'high')
            
        Side Effects:
            - Cria múltiplas threads para execução paralela
            - Atualiza estatísticas globais da simulação
            - Gera logs detalhados de todas as atividades
            - Exibe resumo final com métricas de performance
        """
        self.logger.info("🚀 INICIANDO SIMULAÇÃO MULTI-PORTA")
        
        # Seleciona porta para ataque e define portas normais
        attack_port = self.select_attack_port()
        normal_ports = [p for p in self.monitored_ports if p != attack_port]
        self.attack_stats['normal_traffic_ports'] = normal_ports
        
        self.logger.info(f"📋 Portas com tráfego normal: {normal_ports}")
        self.logger.info(f"⚡ Duração da simulação: {duration} segundos")
        
        # Cria threads para cada tipo de tráfego
        threads = []
        
        # Thread dedicada para ataque DDoS
        attack_thread = threading.Thread(
            target=self.simulate_ddos_attack,
            args=(attack_port, duration, attack_intensity),
            name=f"Attack-Port-{attack_port}"
        )
        threads.append(attack_thread)
        
        # Threads para tráfego normal em cada porta restante
        for port in normal_ports:
            normal_thread = threading.Thread(
                target=self.simulate_normal_traffic,
                args=(port, duration),
                name=f"Normal-Port-{port}"
            )
            threads.append(normal_thread)
        
        # Inicia todas as threads com pequeno delay entre elas
        for thread in threads:
            thread.start()
            time.sleep(0.5)  # Evita sobrecarga inicial
        
        self.logger.info(f"🔄 {len(threads)} threads de simulação iniciadas")
        
        # Aguarda conclusão de todas as threads
        for thread in threads:
            thread.join()
        
        self.logger.info("✅ SIMULAÇÃO FINALIZADA")
        self._print_attack_summary()
    
    def _print_attack_summary(self):
        """
        Exibe resumo detalhado da simulação executada.
        
        Calcula e apresenta métricas importantes da simulação:
        - Porta que foi atacada vs portas com tráfego normal
        - Total de pacotes maliciosos enviados
        - Duração real da simulação
        - Taxa média de pacotes por segundo
        - Formatação visual para fácil leitura
        
        Este resumo ajuda na análise de performance e validação
        dos testes executados pelo sistema de detecção.
        
        Side Effects:
            - Imprime relatório formatado no console
            - Calcula métricas baseadas em attack_stats
        """
        if self.attack_stats['start_time']:
            duration = time.time() - self.attack_stats['start_time']
            
            print("\n" + "="*50)
            print("📊 RESUMO DA SIMULAÇÃO")
            print("="*50)
            print(f"🎯 Porta atacada: {self.attack_stats['target_port']}")
            print(f"📋 Portas normais: {self.attack_stats['normal_traffic_ports']}")
            print(f"📦 Pacotes enviados: {self.attack_stats['packets_sent']}")
            print(f"⏱️ Duração: {duration:.1f}s")
            print(f"📈 Taxa média: {self.attack_stats['packets_sent']/duration:.1f} pps")
            print("="*50 + "\n")
