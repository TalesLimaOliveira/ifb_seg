# Sistema de Detecção de Ataques DDoS Multi-Porta

## Visão Geral do Projeto

- **Sistema de monitoramento e detecção de ataques DDoS** em tempo real
- **Arquitetura modular** com componentes independentes e bem definidos
- **Simulação de ataques** para testes e validação do sistema
- **Dashboard web** para monitoramento visual das atividades
- **Sistema de notificações** para alertas em tempo real

## Funcionalidades Principais

- **Detecção de ataques DDoS** em múltiplas portas simultaneamente
- **Bloqueio automático** de IPs maliciosos via iptables
- **Simulação de tráfego** normal e malicioso para testes
- **Monitoramento em tempo real** com estatísticas detalhadas
- **Interface web** para visualização de dados e controle do sistema
- **Sistema de logs** centralizados para auditoria e análise
- **Configuração flexível** via arquivo YAML

## Estrutura dos Arquivos

### 📂 Configuração
- **`config.yaml`** - Configurações do sistema (portas, thresholds, timeouts)
- **`requirements.txt`** - Dependências Python necessárias

### 📂 Código Principal (`src/`)

#### **`main.py`** - Orquestrador Principal
- **Responsabilidade**: Coordena todos os componentes do sistema
- **Funcionalidades**:
  - Inicialização e configuração do sistema
  - Gerenciamento do ciclo de vida dos componentes
  - Coordenação entre detector, simulador e dashboard

#### **`utils.py`** - Utilitários Compartilhados
- **Responsabilidade**: Funções auxiliares utilizadas por todo o sistema
- **Funcionalidades**:
  - Carregamento de configurações YAML
  - Setup do sistema de logging
  - Validação de configurações
  - Formatação segura de mensagens de log

#### **`multi_port_detector.py`** - Engine de Detecção
- **Responsabilidade**: Núcleo da detecção de ataques DDoS
- **Funcionalidades**:
  - Monitoramento de pacotes em tempo real
  - Análise de padrões de tráfego suspeito
  - Detecção de ataques em múltiplas portas
  - Geração de estatísticas de rede

#### **`port_manager.py`** - Gerenciador de Bloqueios
- **Responsabilidade**: Controle de acesso via iptables
- **Funcionalidades**:
  - Bloqueio automático de IPs maliciosos
  - Desbloqueio temporal de IPs
  - Gerenciamento de whitelist
  - Controle de regras de firewall

#### **`notification_system.py`** - Sistema de Alertas
- **Responsabilidade**: Notificações e alertas do sistema
- **Funcionalidades**:
  - Envio de alertas em tempo real
  - Logging estruturado de eventos
  - Notificações via console e arquivo
  - Formatação de mensagens de alerta

#### **`multi_port_attacker.py`** - Simulador de Ataques
- **Responsabilidade**: Simulação de tráfego para testes
- **Funcionalidades**:
  - Simulação de ataques DDoS realísticos
  - Geração de tráfego normal para baseline
  - Testes de múltiplas portas simultaneamente
  - Estatísticas de simulação

#### **`dashboard.py`** - Interface Web
- **Responsabilidade**: Dashboard web para monitoramento
- **Funcionalidades**:
  - Interface visual em tempo real
  - Gráficos de estatísticas de rede
  - Controle manual de bloqueios
  - Visualização de logs e alertas

### 📂 Interface (`templates/`)
- **`dashboard.html`** - Interface web com gráficos e controles

### 📂 Logs (`logs/`)
- Arquivos de log separados por componente para melhor organização

## Tecnologias Utilizadas

- **Python 3.x** - Linguagem principal
- **Flask/Flask-SocketIO** - Framework web para dashboard
- **Scapy** - Captura e análise de pacotes (com fallback para simulação)
- **iptables** - Controle de firewall no Linux
- **YAML** - Formato de configuração
- **Threading** - Execução paralela de componentes
- **Logging** - Sistema de logs integrado

## Fluxo de Funcionamento

1. **Inicialização** - `main.py` carrega configurações e inicializa componentes
2. **Monitoramento** - `multi_port_detector.py` monitora tráfego de rede
3. **Detecção** - Análise de padrões suspeitos em múltiplas portas
4. **Bloqueio** - `port_manager.py` bloqueia IPs maliciosos via iptables
5. **Notificação** - `notification_system.py` envia alertas em tempo real
6. **Visualização** - `dashboard.py` apresenta dados na interface web
7. **Simulação** - `multi_port_attacker.py` gera tráfego para testes

## Características Técnicas

- **Arquitetura modular** com responsabilidades bem definidas
- **Thread-safe** para operações concorrentes
- **Configuração flexível** via arquivo YAML
- **Sistema de logging robusto** com diferentes níveis
- **Tratamento de erros** abrangente
- **Fallback modes** para ambientes sem Scapy
- **Interface responsiva** com atualizações em tempo real

## Segurança e Confiabilidade

- **Validação de entrada** em todos os componentes
- **Sanitização de logs** para prevenir injection
- **Whitelist de IPs** para evitar auto-bloqueio
- **Timeouts configuráveis** para desbloqueio automático
- **Logs auditáveis** para análise forense
- **Modo de simulação** para testes seguros
