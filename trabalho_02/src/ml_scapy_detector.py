import time
from collections import defaultdict, deque
from threading import Thread
from scapy.all import sniff, IP, conf, L3RawSocket
from sklearn.ensemble import IsolationForest
import numpy as np

# Configurações
MAX_PACKETS_PER_IP = 100
TIME_WINDOW = 10  # segundos
ALERTED_IPS = set()

# Histórico de timestamps por IP
ip_packet_history = defaultdict(lambda: deque())

# Para ML: histórico de contagem de pacotes por IP
ip_packet_counts = defaultdict(list)


def packet_callback(pkt):
    if IP in pkt:
        ip = pkt[IP].src
        now = time.time()
        ip_packet_history[ip].append(now)
        # Remove timestamps fora da janela
        while ip_packet_history[ip] and now - ip_packet_history[ip][0] > TIME_WINDOW:
            ip_packet_history[ip].popleft()
        count = len(ip_packet_history[ip])
        ip_packet_counts[ip].append(count)
        if count > MAX_PACKETS_PER_IP and ip not in ALERTED_IPS:
            print(f"[ALERTA] Possível ataque DDoS detectado do IP (scapy): {ip}")
            ALERTED_IPS.add(ip)


def start_packet_sniffing():
    print("Monitorando pacotes em tempo real com scapy...")
    # Força uso de L3RawSocket para compatibilidade com Windows sem Npcap
    conf.L3socket = L3RawSocket
    sniff(prn=packet_callback, store=0, filter="ip")


def run_ml_detection():
    print("Iniciando detecção anômala (IsolationForest)...")
    while True:
        time.sleep(TIME_WINDOW)
        # Prepara dados para ML
        data = np.array([[counts[-1]] for counts in ip_packet_counts.values() if counts])
        if len(data) > 2:
            model = IsolationForest(contamination=0.1)
            preds = model.fit_predict(data)
            for i, (ip, counts) in enumerate(ip_packet_counts.items()):
                if len(counts) > 0 and preds[i] == -1:
                    print(f"[ML ALERTA] IP anômalo detectado pelo modelo: {ip} (pacotes na janela: {counts[-1]})")


def main():
    Thread(target=run_ml_detection, daemon=True).start()
    start_packet_sniffing()

if __name__ == "__main__":
    main()
