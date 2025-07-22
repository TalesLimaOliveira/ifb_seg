# Simulador de Ataques DDoS Multi-Porta - Simula ataques para testar o sistema de detecção

import logging
import random
import threading
import time


class MultiPortAttacker:
    # Simulador de ataques DDoS para testes do sistema
    
    def __init__(self, config):
        self.config = config
        self.monitored_ports = list(config['detection']['ports'].keys())
        self.attack_port = None
        self.logger = logging.getLogger(__name__)
        
        self.attack_stats = {
            'start_time': None,
            'packets_sent': 0,
            'target_port': None,
            'normal_traffic_ports': []
        }

    def select_attack_port(self):
        # Seleciona porta aleatória para ataque
        self.attack_port = random.choice(self.monitored_ports)
        self.attack_stats['target_port'] = self.attack_port
        
        port_info = self.config['detection']['ports'][self.attack_port]
        self.logger.info(
            f"🎯 PORTA SELECIONADA PARA ATAQUE: {self.attack_port} "
            f"({port_info['protocol']} - {port_info['description']})"
        )
        
        return self.attack_port

    def simulate_normal_traffic(self, port, duration=60):
        # Simula tráfego normal em uma porta
        port_info = self.config['detection']['ports'][port]
        self.logger.info(f"✅ Iniciando tráfego normal na porta {port} ({port_info['protocol']})")
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            time.sleep(random.uniform(1, 5))
            packet_count += 1
            
            if packet_count % 10 == 0:
                self.logger.debug(f"✅ Tráfego normal na porta {port}: {packet_count} pacotes")
        
        self.logger.info(f"✅ Tráfego normal finalizado na porta {port}: {packet_count} pacotes")

    def simulate_ddos_attack(self, port, duration=60, intensity='high'):
        # Simula ataque DDoS em uma porta específica
        port_info = self.config['detection']['ports'][port]
        max_requests = port_info['max_requests']
        
        if intensity == 'low':
            interval = 0.1
            burst_size = max_requests + 20
        elif intensity == 'medium':
            interval = 0.05
            burst_size = max_requests + 50
        else:  # high
            interval = 0.01
            burst_size = max_requests + 100
        
        self.logger.warning(
            f"💥 INICIANDO ATAQUE DDoS na porta {port} "
            f"({port_info['protocol']}) - Intensidade: {intensity.upper()}"
        )
        
        start_time = time.time()
        self.attack_stats['start_time'] = start_time
        packet_count = 0
        
        while time.time() - start_time < duration:
            for _ in range(burst_size):
                time.sleep(interval)
                packet_count += 1
                self.attack_stats['packets_sent'] = packet_count
                
                if packet_count % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = packet_count / elapsed
                    self.logger.warning(
                        f"🔥 Ataque em andamento na porta {port}: "
                        f"{packet_count} pacotes ({rate:.1f} pps)"
                    )
            
            time.sleep(random.uniform(0.5, 2))
        
        self.logger.warning(
            f"💥 ATAQUE FINALIZADO na porta {port}: "
            f"{packet_count} pacotes enviados em {duration}s"
        )

    def run_simulation(self, duration=120, attack_intensity='high'):
        # Executa simulação completa de ataque multi-porta
        self.logger.info("🚀 INICIANDO SIMULAÇÃO MULTI-PORTA")
        
        attack_port = self.select_attack_port()
        normal_ports = [p for p in self.monitored_ports if p != attack_port]
        self.attack_stats['normal_traffic_ports'] = normal_ports
        
        self.logger.info(f"📋 Portas com tráfego normal: {normal_ports}")
        self.logger.info(f"⚡ Duração da simulação: {duration} segundos")
        
        threads = []
        
        attack_thread = threading.Thread(
            target=self.simulate_ddos_attack,
            args=(attack_port, duration, attack_intensity),
            name=f"Attack-Port-{attack_port}"
        )
        threads.append(attack_thread)
        
        for port in normal_ports:
            normal_thread = threading.Thread(
                target=self.simulate_normal_traffic,
                args=(port, duration),
                name=f"Normal-Port-{port}"
            )
            threads.append(normal_thread)
        
        for thread in threads:
            thread.start()
            time.sleep(0.5)
        
        self.logger.info(f"🔄 {len(threads)} threads de simulação iniciadas")
        
        for thread in threads:
            thread.join()
        
        self.logger.info("✅ SIMULAÇÃO FINALIZADA")
        self._print_attack_summary()

    def _print_attack_summary(self):
        # Exibe resumo da simulação executada
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
