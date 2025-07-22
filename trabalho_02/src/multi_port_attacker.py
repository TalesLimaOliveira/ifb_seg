import time 
import random 
import threading
import logging  
from datetime import datetime

class MultiPortAttacker:
    def __init__(self, config):
        # Armazena configurações do sistema
        self.config = config
        # Lista das portas que serão monitoradas
        self.monitored_ports = list(config['detection']['ports'].keys())
        # Porta que será atacada (definida durante execução)
        self.attack_port = None
        # Logger para registrar eventos
        self.logger = logging.getLogger(__name__)
        
        # Dicionário para armazenar estatísticas da simulação
        self.attack_stats = {
            'start_time': None,
            'packets_sent': 0,
            'target_port': None,
            'normal_traffic_ports': []
        }
    

    def select_attack_port(self):
        # Escolhe uma porta aleatória da lista de portas monitoradas
        self.attack_port = random.choice(self.monitored_ports)
        # Salva a porta escolhida nas estatísticas
        self.attack_stats['target_port'] = self.attack_port
        
        # Busca informações da porta para o log
        port_info = self.config['detection']['ports'][self.attack_port]
        # Registra no log qual porta foi selecionada
        self.logger.info(
            f"🎯 PORTA SELECIONADA PARA ATAQUE: {self.attack_port} "
            f"({port_info['protocol']} - {port_info['description']})"
        )
        
        return self.attack_port
    

    def simulate_normal_traffic(self, port, duration=60):
        # Busca informações da porta
        port_info = self.config['detection']['ports'][port]
        # Log de início do tráfego normal
        self.logger.info(f"✅ Iniciando tráfego normal na porta {port} ({port_info['protocol']})")
        
        # Marca tempo de início e contador de pacotes
        start_time = time.time()
        packet_count = 0
        
        # Loop principal - simula tráfego até duração especificada
        while time.time() - start_time < duration:
            # Pausa entre 1-5 segundos (comportamento normal)
            time.sleep(random.uniform(1, 5))
            
            # Incrementa contador de pacotes
            packet_count += 1
            # Log a cada 10 pacotes para acompanhar progresso
            if packet_count % 10 == 0:
                self.logger.debug(f"✅ Tráfego normal na porta {port}: {packet_count} pacotes")
        
        # Log final com total de pacotes enviados
        self.logger.info(f"✅ Tráfego normal finalizado na porta {port}: {packet_count} pacotes")
    

    def simulate_ddos_attack(self, port, duration=60, intensity='high'):
        # Busca informações da porta e limite máximo configurado
        port_info = self.config['detection']['ports'][port]
        max_requests = port_info['max_requests']
        
        # Define parâmetros do ataque baseado na intensidade
        if intensity == 'low':
            interval = 0.1  # 10 pacotes por segundo
            burst_size = max_requests + 20
        elif intensity == 'medium':
            interval = 0.05  # 20 pacotes por segundo
            burst_size = max_requests + 50
        else:  # high
            interval = 0.01  # 100 pacotes por segundo
            burst_size = max_requests + 100
        
        # Log de início do ataque
        self.logger.warning(
            f"💥 INICIANDO ATAQUE DDoS na porta {port} "
            f"({port_info['protocol']}) - Intensidade: {intensity.upper()}"
        )
        
        # Inicializa controle de tempo e estatísticas
        start_time = time.time()
        self.attack_stats['start_time'] = start_time
        packet_count = 0
        
        # Loop principal do ataque
        while time.time() - start_time < duration:
            # Envia rajada de pacotes conforme intensidade
            for _ in range(burst_size):
                time.sleep(interval)  # Intervalo entre pacotes
                packet_count += 1     # Conta pacotes enviados
                self.attack_stats['packets_sent'] = packet_count
                
                # Log de progresso a cada 100 pacotes
                if packet_count % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = packet_count / elapsed
                    self.logger.warning(
                        f"🔥 Ataque em andamento na porta {port}: "
                        f"{packet_count} pacotes ({rate:.1f} pps)"
                    )
            
        # Pausa entre rajadas para simular comportamento real
        time.sleep(random.uniform(0.5, 2))
        
        # Log final com estatísticas do ataque
        self.logger.warning(
            f"💥 ATAQUE FINALIZADO na porta {port}: "
            f"{packet_count} pacotes enviados em {duration}s"
        )
    

    def run_simulation(self, duration=120, attack_intensity='high'):
        # Log de início da simulação
        self.logger.info("🚀 INICIANDO SIMULAÇÃO MULTI-PORTA")
        
        # Seleciona uma porta para atacar e define as outras como normais
        attack_port = self.select_attack_port()
        normal_ports = [p for p in self.monitored_ports if p != attack_port]
        self.attack_stats['normal_traffic_ports'] = normal_ports
        
        # Logs informativos sobre a configuração
        self.logger.info(f"📋 Portas com tráfego normal: {normal_ports}")
        self.logger.info(f"⚡ Duração da simulação: {duration} segundos")
        
        # Lista para armazenar todas as threads
        threads = []
        
        # Cria thread para simular o ataque DDoS
        attack_thread = threading.Thread(
            target=self.simulate_ddos_attack,
            args=(attack_port, duration, attack_intensity),
            name=f"Attack-Port-{attack_port}"
        )
        threads.append(attack_thread)
        
        # Cria threads para tráfego normal em cada porta restante
        for port in normal_ports:
            normal_thread = threading.Thread(
                target=self.simulate_normal_traffic,
                args=(port, duration),
                name=f"Normal-Port-{port}"
            )
            threads.append(normal_thread)
        
        # Inicia todas as threads com pequeno delay para evitar sobrecarga
        for thread in threads:
            thread.start()
            time.sleep(0.5)  # Delay entre starts
        
        self.logger.info(f"🔄 {len(threads)} threads de simulação iniciadas")
        
        # Aguarda todas as threads terminarem
        for thread in threads:
            thread.join()
        
        # Log de conclusão e exibe resumo
        self.logger.info("✅ SIMULAÇÃO FINALIZADA")
        self._print_attack_summary()
    
    
    def _print_attack_summary(self):
        # Verifica se a simulação foi executada
        if self.attack_stats['start_time']:
            # Calcula duração real da simulação
            duration = time.time() - self.attack_stats['start_time']
            
            # Imprime relatório formatado
            print("\n" + "="*50)
            print("📊 RESUMO DA SIMULAÇÃO")
            print("="*50)
            print(f"🎯 Porta atacada: {self.attack_stats['target_port']}")
            print(f"📋 Portas normais: {self.attack_stats['normal_traffic_ports']}")
            print(f"📦 Pacotes enviados: {self.attack_stats['packets_sent']}")
            print(f"⏱️ Duração: {duration:.1f}s")
            print(f"📈 Taxa média: {self.attack_stats['packets_sent']/duration:.1f} pps")
            print("="*50 + "\n")
