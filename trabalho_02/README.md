# 🌟 Segurança da Computação - Instituto Federal de Brasília 🌟

## Detector e Simulador de Ataques DDoS

Este projeto contém um detector básico de ataques DDoS em tempo real, um detector de pacotes com machine learning e um simulador de ataque para testes.

---

## PRÉ-REQUISITOS

- Python 3.7+
- Permissão de root (apenas para bloqueio automático de IP via iptables no Linux)
- `iptables` instalado (Linux, apenas para bloqueio automático)
- Recomenda-se ambiente Linux para bloqueio automático de IPs
- Para captura de pacotes/scapy no Windows, execute o terminal como Administrador

---

## INSTALAÇÃO

Clone o repositório e acesse a pasta:

```sh
 git clone <repo-url>
 cd trabalho_02
```

Crie e ative um ambiente virtual (opcional, mas recomendado):

```sh
python -m venv venv
venv\Scripts\activate  # Windows
# ou
source venv/bin/activate  # Linux/macOS
```

Instale as dependências:

```sh
pip install -r requirements.txt
```

---

## USO

### Execução automática de toda a simulação

Execute o arquivo principal para rodar os detectores e o simulador de ataque juntos:

```sh
python src/main.py
```

- Isso irá iniciar:
  - O detector de logs (`detector.py`)
  - O detector de pacotes com machine learning (`ml_scapy_detector.py`)
  - O simulador de ataque (`attacker.py`)
- O ataque será simulado automaticamente e os detectores mostrarão alertas em tempo real.
- O relatório dos IPs mais ativos será salvo em `ddos_report.json`.

### Execução manual (opcional)

Você pode rodar cada componente separadamente em terminais diferentes:

1. Detector de logs:
    ```sh
    python src/detector.py
    ```
2. Detector de pacotes (scapy + ML):
    ```sh
    python src/ml_scapy_detector.py
    ```
3. Simulador de ataque:
    ```sh
    python src/attacker.py --malicious-ip 192.168.1.100 --requests 200 --interval 0.05
    ```

---

## PERSONALIZAÇÃO

- Altere `MAX_REQUESTS_PER_IP` e `TIME_WINDOW` em `src/detector.py` para ajustar a sensibilidade do detector de logs.
- Altere `MAX_PACKETS_PER_IP` e `TIME_WINDOW` em `src/ml_scapy_detector.py` para ajustar a sensibilidade do detector de pacotes.
- O simulador pode ser ajustado via argumentos de linha de comando.

---

## OBSERVAÇÕES

- O bloqueio automático de IPs requer permissão de root e funciona apenas em sistemas Linux com iptables.
- Para testes em Windows, o bloqueio será apenas simulado (mensagem no console).
- Para captura de pacotes/scapy no Windows, execute o terminal como Administrador.
- O detector de pacotes pode não capturar todos os tipos de pacotes em todas as interfaces no Windows.

---

## AUTORIA

Projeto acadêmico - IFB Segurança da Computação