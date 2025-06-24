import subprocess
import sys
import time
from threading import Thread

# Função para rodar um script em um novo processo
def run_script(script, args=None):
    cmd = [sys.executable, script]
    if args:
        cmd += args
    return subprocess.Popen(cmd)

if __name__ == "__main__":
    print("Iniciando simulação de ataque DDoS e detecção em tempo real...")
    # Inicia o detector de logs
    detector_proc = run_script("src/detector.py")
    # Inicia o detector de pacotes (scapy + ML)
    ml_scapy_proc = run_script("src/ml_scapy_detector.py")
    # Aguarda um pouco para os detectores iniciarem
    time.sleep(2)
    # Inicia o atacante
    attacker_proc = run_script("src/attacker.py", ["--malicious-ip", "192.168.1.100", "--requests", "200", "--interval", "0.05"])

    try:
        # Aguarda o atacante terminar
        attacker_proc.wait()
        print("Ataque simulado finalizado. Você pode encerrar os detectores com Ctrl+C.")
    except KeyboardInterrupt:
        print("Encerrando todos os processos...")
    finally:
        detector_proc.terminate()
        ml_scapy_proc.terminate()
        attacker_proc.terminate()
