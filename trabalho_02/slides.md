# Apresentação: Detector e Simulador de Ataques DDoS

---

## Slide 1: Título
- Detector e Simulador de Ataques DDoS
- Segurança da Computação - IFB

---

## Slide 2: Motivação
- Ataques DDoS são comuns e perigosos
- Podem derrubar serviços e causar prejuízos
- Importância de detectar e mitigar rapidamente

---

## Slide 3: Objetivo do Projeto
- Simular ataques DDoS
- Detectar ataques em tempo real
- Gerar relatórios e bloquear IPs suspeitos

---

## Slide 4: Estrutura do Projeto
- `detector.py`: monitora logs de acesso
- `ml_scapy_detector.py`: monitora pacotes de rede (com ML)
- `attacker.py`: simula ataque DDoS
- `main.py`: executa tudo automaticamente

---

## Slide 5: Funcionamento Geral
- O atacante gera tráfego malicioso e normal
- Detectores analisam logs e pacotes em tempo real
- Alertas e bloqueios são disparados automaticamente

---

## Slide 6: Como Rodar o Projeto
- Instale dependências: `pip install -r requirements.txt`
- Execute: `python src/main.py`
- Todos os módulos iniciam automaticamente

---

## Slide 7: Pré-requisitos
- Python 3.7+
- (Linux) Permissão de root para bloqueio de IP
- (Windows) Npcap instalado para captura de pacotes

---

## Slide 8: Detector de Logs (`detector.py`)
- Monitora `access.log` em tempo real
- Conta requisições por IP
- Alerta e bloqueia IPs suspeitos via iptables

---

## Slide 9: Detector de Pacotes (`ml_scapy_detector.py`)
- Usa Scapy para capturar pacotes de rede
- Conta pacotes por IP em janelas de tempo
- Alerta se um IP exceder o limite

---

## Slide 10: Machine Learning no Detector
- IsolationForest detecta padrões anômalos
- Modelo é treinado em tempo real
- Alerta para IPs com comportamento fora do padrão

---

## Slide 11: Simulador de Ataque (`attacker.py`)
- Gera tráfego malicioso e normal
- Escreve no `access.log` para simular requisições
- Permite configurar IP, quantidade e intervalo

---

## Slide 12: Arquivo Principal (`main.py`)
- Inicia todos os módulos em paralelo
- Garante que detectores estejam prontos antes do ataque
- Finaliza processos ao término do ataque

---

## Slide 13: Personalização
- Ajuste sensibilidade alterando `MAX_REQUESTS_PER_IP` e `TIME_WINDOW`
- Modifique argumentos do atacante para simular diferentes cenários
- Relatórios salvos em `ddos_report.json`

---

## Slide 14: Utilidade Prática
- Testar e treinar equipes de segurança
- Validar regras de firewall e detecção
- Base para projetos de pesquisa em cibersegurança

---

## Slide 15: Limitações
- Bloqueio automático só funciona em Linux
- Captura de pacotes pode exigir permissões/admin
- Machine learning é não supervisionado (unsupervised)

---

## Slide 16: Possíveis Extensões
- Adicionar interface web para monitoramento
- Salvar logs de alertas em banco de dados
- Integrar com sistemas de resposta automática

---

## Slide 17: Exemplo de Alerta
- [Imagem: Console mostrando alerta de DDoS]
- Mensagem: "[ALERTA] Possível ataque DDoS detectado do IP: 192.168.1.100"

---

## Slide 18: Exemplo de Relatório
- [Imagem: Trecho do arquivo `ddos_report.json`]
- Lista de IPs mais ativos e quantidade de requisições

---

## Slide 19: Dicas para Demonstração
- Execute o projeto em terminais separados para visualizar alertas
- Altere parâmetros para ver diferentes comportamentos
- Teste em Linux para bloqueio real de IPs

---

## Slide 20: Conclusão
- Projeto didático e prático
- Demonstra conceitos de detecção e resposta a DDoS
- Base para estudos e aprimoramentos futuros
