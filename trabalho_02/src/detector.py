import time
import re
import json
from collections import deque, defaultdict
import subprocess
import argparse
from threading import Thread

LOG_FILE = "access.log"
MAX_REQUESTS_PER_IP = 100
TIME_WINDOW = 10  # segundos
BLOCKED_IPS = set()
REPORT_FILE = "ddos_report.json"

ip_history = defaultdict(lambda: deque(maxlen=MAX_REQUESTS_PER_IP * 2))

def block_ip(ip):
    if ip not in BLOCKED_IPS:
        print(f"[ALERTA] Bloqueando IP suspeito: {ip}")
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        except Exception as e:
            print(f"[ERRO] Falha ao bloquear IP (requer root): {e}")
        BLOCKED_IPS.add(ip)

def parse_ip(line):
    match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", line)
    if match:
        return match.group(1)
    return None

def monitor_log():
    print("Monitorando log em tempo real...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            ip = parse_ip(line)
            if ip:
                now = time.time()
                ip_history[ip].append(now)
                while ip_history[ip] and now - ip_history[ip][0] > TIME_WINDOW:
                    ip_history[ip].popleft()
                if len(ip_history[ip]) > MAX_REQUESTS_PER_IP:
                    print(f"[ALERTA] Possível ataque DDoS detectado do IP: {ip}")
                    block_ip(ip)

def generate_report():
    report = sorted(
        ((ip, len(times)) for ip, times in ip_history.items()),
        key=lambda x: x[1], reverse=True
    )
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Relatório salvo em {REPORT_FILE}")

def main():
    parser = argparse.ArgumentParser(description="Detector de DDoS em tempo real")
    parser.add_argument("--report-interval", type=int, default=10, help="Intervalo de geração de relatório (s)")
    args = parser.parse_args()

    Thread(target=monitor_log, daemon=True).start()
    try:
        while True:
            time.sleep(args.report_interval)
            generate_report()
    except KeyboardInterrupt:
        print("Encerrando detector DDoS.")

if __name__ == "__main__":
    main()