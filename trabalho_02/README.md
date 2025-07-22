# 🛡️ Sistema Avançado de Detecção DDoS

Um sistema completo de detecção e prevenção de ataques DDoS com interface web em tempo real, desenvolvido para monitoramento de múltiplas portas de rede simultaneamente.

## 📋 Visão Geral

Este sistema monitora tráfego de rede em tempo real, detecta padrões de ataque DDoS e permite gerenciamento manual de portas através de um dashboard web interativo. Inclui simulador de ataques para testes e validação do sistema de detecção.

## 🏗️ Arquitetura do Sistema

```
📁 trabalho_02/
├── 📄 config.yaml          # Configurações do sistema
├── 📄 requirements.txt     # Dependências Python
├── 📁 src/                # Código fonte principal
│   ├── 📄 main.py         # Ponto de entrada do sistema
│   ├── 📄 dashboard.py    # Interface web Flask + WebSocket
│   ├── 📄 multi_port_detector.py  # Detector de ataques DDoS
│   ├── 📄 multi_port_attacker.py  # Simulador de ataques
│   ├── 📄 port_manager.py         # Gerenciador de bloqueio de portas
│   ├── 📄 notification_system.py  # Sistema de notificações
│   └── 📄 utils.py               # Funções utilitárias
├── 📁 templates/          # Templates HTML
│   └── 📄 dashboard.html  # Interface do dashboard
└── 📁 logs/              # Arquivos de log do sistema
```

## 🔧 Componentes Principais

### 🎯 `main.py` - Orquestrador Principal
- **Função**: Ponto de entrada que inicializa todos os componentes
- **Responsabilidades**: 
  - Carrega configurações do `config.yaml`
  - Inicializa detector, gerenciador de portas e dashboard
  - Gerencia ciclo de vida do sistema

### 🌐 `dashboard.py` - Interface Web
- **Função**: Dashboard web com Flask + SocketIO para tempo real
- **Funcionalidades**:
  - Interface de monitoramento de portas (22, 80, 443)
  - Simulação de ataques DDoS direcionados
  - Bloqueio/desbloqueio manual de portas
  - Logs em tempo real via WebSocket
- **Rotas Principais**: `/` (dashboard), WebSocket para atualizações

### 🔍 `multi_port_detector.py` - Detector de Ataques
- **Função**: Monitora tráfego de rede e detecta padrões DDoS
- **Como Funciona**:
  - Captura pacotes com Scapy (ou modo simulação)
  - Analisa thresholds configuráveis por porta
  - Mantém estatísticas de tráfego em tempo real
  - Notifica sistema quando ataque é detectado

### ⚡ `multi_port_attacker.py` - Simulador de Ataques
- **Função**: Gera tráfego sintético para testar o detector
- **Capacidades**:
  - Simula ataques DDoS em portas específicas
  - Gera múltiplos IPs atacantes falsos
  - Controle de duração e intensidade

### 🔒 `port_manager.py` - Gerenciador de Portas
- **Função**: Controla bloqueio/desbloqueio de portas via iptables
- **Funcionalidades**:
  - Integração com firewall do sistema
  - Whitelist de IPs confiáveis
  - Desbloqueio automático por tempo
  - Callbacks para notificações de mudança

### 📢 `notification_system.py` - Sistema de Notificações
- **Função**: Centraliza alertas e notificações do sistema
- **Tipos**: Email, logs estruturados, webhooks

### 🛠️ `utils.py` - Utilitários
- **Função**: Funções auxiliares compartilhadas
- **Inclui**: 
  - Carregamento de configurações YAML
  - Logging com suporte UTF-8 (Windows)
  - Funções de validação e formatação

## ⚙️ Configuração

### `config.yaml` - Configurações Centralizadas
```yaml
detection:
  time_window: 10          # Janela de análise (segundos)
  ports:                   # Configuração por porta
    80: {max_requests: 100, protocol: "HTTP"}
    443: {max_requests: 150, protocol: "HTTPS"}
    22: {max_requests: 50, protocol: "SSH"}

blocking:
  unblock_time: 300        # Auto-desbloqueio (segundos)
  whitelist_ips: []        # IPs sempre permitidos

notifications:
  email_enabled: false     # Notificações por email
  webhook_url: ""         # URL para webhooks
```

## 🚀 Como Utilizar

### 1. Instalação
```bash
pip install -r requirements.txt
```

### 2. Execução
```bash
python src/main.py
```

### 3. Acesso ao Dashboard
- Abra: `http://localhost:5000`
- Interface mostra status em tempo real das 3 portas monitoradas

### 4. Funcionalidades Disponíveis

#### 🎯 Simulação de Ataques
1. Selecione uma porta alvo (22, 80 ou 443)
2. Clique "🚨 Iniciar Ataque"
3. Sistema simula DDoS **apenas na porta selecionada**
4. Outras portas mantêm tráfego normal

#### 🔐 Gerenciamento de Portas
- **Fechar Porta**: Clique "🔒 Fechar Porta" para bloquear
- **Abrir Porta**: Clique "🔓 Abrir Porta" para desbloquear
- Status atualiza automaticamente via WebSocket

#### 📊 Monitoramento
- **Cards de Porta**: Status visual (Aberta/Fechada/Sob Ataque)
- **Estatísticas**: Pacotes totais e IPs únicos por porta
- **Logs em Tempo Real**: Eventos do sistema aparecem automaticamente

## 🔄 Fluxo de Funcionamento

1. **Inicialização**: `main.py` carrega configurações e inicializa componentes
2. **Monitoramento**: `multi_port_detector.py` monitora tráfego continuamente
3. **Detecção**: Quando threshold é ultrapassado, alerta é gerado
4. **Resposta**: `port_manager.py` pode bloquear porta automaticamente
5. **Visualização**: `dashboard.py` mostra tudo em tempo real
6. **Notificação**: `notification_system.py` envia alertas configurados

## 🎨 Personalização

### Cores do Dashboard
Edite `templates/dashboard.html` na seção `<style>`:
- **Background**: Modifique `.container { background-color: #valor; }`
- **Botões**: Altere `.btn-primary { background-color: #valor; }`
- **Cards**: Mude `.card { background-color: #valor; }`

### Thresholds de Detecção
Ajuste `config.yaml` na seção `detection.ports`:
```yaml
80:
  max_requests: 200  # Aumentar tolerance
```

## 📝 Logs e Monitoramento

- **Logs do Sistema**: `logs/ddos_system.log`
- **Logs de Alertas**: `logs/ddos_alerts.log`
- **Console**: Logs em tempo real com emoji-safe encoding

## 🔧 Dependências Principais

- **Flask + SocketIO**: Interface web em tempo real
- **Scapy**: Captura de pacotes de rede (opcional)
- **PyYAML**: Processamento de configurações
- **Threading**: Processamento assíncrono

## ⚠️ Notas Importantes

- **Windows**: Sistema inclui tratamento especial para encoding UTF-8
- **Privilégios**: Algumas funções podem requerer privilégios administrativos
- **Modo Simulação**: Funciona sem Scapy instalado para demonstrações
- **Firewall**: Integração com iptables para bloqueio real de portas

---

**Desenvolvido para disciplina de Segurança - IFB**  
*Sistema educacional para estudo de detecção e prevenção DDoS*
