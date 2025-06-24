import time
import argparse
import random

def simulate_attack(log_file, malicious_ip, total_requests, interval, normal_ips=10):
    print(f"Simulando ataque DDoS do IP {malicious_ip} para {log_file}...")
    with open(log_file, "a") as f:
        for i in range(total_requests):
            if i % 2 == 0:
                ip = malicious_ip
            else:
                ip = f"10.0.0.{random.randint(1, normal_ips)}"
            f.write(f"{ip} - - [24/Jun/2025:12:00:{i%60:02d} +0000] \"GET / HTTP/1.1\" 200 1234\n")
            time.sleep(interval if ip == malicious_ip else interval * 2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulador de ataque DDoS para teste do detector")
    parser.add_argument("--log-file", default="access.log", help="Arquivo de log a ser atacado")
    parser.add_argument("--malicious-ip", default="192.168.1.100", help="IP malicioso")
    parser.add_argument("--requests", type=int, default=200, help="Total de requisições")
    parser.add_argument("--interval", type=float, default=0.05, help="Intervalo entre requisições do atacante (s)")
    args = parser.parse_args()
    simulate_attack(args.log_file, args.malicious_ip, args.requests, args.interval)