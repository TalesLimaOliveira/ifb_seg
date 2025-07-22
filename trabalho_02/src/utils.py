"""
Módulo de Utilitários do Sistema de Detecção DDoS

Este módulo centraliza funções utilitárias compartilhadas por todos os
componentes do sistema, incluindo:

- Carregamento e validação de configurações YAML
- Configuração padronizada de sistema de logging
- Formatação e validação de endereços IP
- Mapeamento de portas para protocolos conhecidos
- Funções de formatação de dados (bytes, taxa de pacotes)
- Cálculos de métricas de rede

Todas as funções são projetadas para serem reutilizáveis e robustas,
com tratamento adequado de erros e validação de entrada.

Autor: Sistema de Segurança IFB
Data: 2024
"""

import yaml
import logging
import os
from pathlib import Path


def load_configuration(config_file='config.yaml'):
    """
    Carrega configurações do arquivo YAML com validação robusta.
    
    Tenta carregar configurações de um arquivo YAML, com tratamento
    adequado de erros e validação de formato. Suporta encoding UTF-8
    para caracteres especiais.
    
    Args:
        config_file (str): Caminho relativo ou absoluto para arquivo de configuração
        
    Returns:
        dict: Dicionário com configurações carregadas, ou None se houver erro
        
    Raises:
        yaml.YAMLError: Se arquivo YAML tem formato inválido
        FileNotFoundError: Se arquivo não existe no caminho especificado
        Exception: Para outros erros inesperados
        
    Example:
        >>> config = load_configuration('config.yaml')
        >>> if config:
        ...     ports = config['detection']['ports']
    """
    try:
        config_path = Path(config_file)
        if not config_path.exists():
            print(f"❌ Arquivo de configuração não encontrado: {config_file}")
            return None
            
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            print(f"✅ Configurações carregadas de: {config_file}")
            return config
            
    except yaml.YAMLError as e:
        print(f"❌ Erro ao processar arquivo YAML: {e}")
        return None
    except Exception as e:
        print(f"❌ Erro inesperado ao carregar configurações: {e}")
        return None


def setup_logging(log_file='logs/ddos_system.log', level=logging.INFO):
    """
    Configura sistema de logging padronizado para todo o projeto.
    
    Estabelece configuração de logging unificada com:
    - Formato padronizado de timestamps e mensagens
    - Saída tanto para arquivo quanto para console
    - Encoding UTF-8 para suporte a caracteres especiais
    - Tratamento robusto para problemas de encoding no Windows
    
    O sistema de logging é configurado de forma global, afetando
    todos os loggers criados posteriormente no projeto.
    
    Args:
        log_file (str): Caminho para arquivo de log (padrão: 'logs/ddos_system.log')
        level (int): Nível de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Side Effects:
        - Cria diretório logs/ se não existir
        - Configura handlers globais de logging
        - Define formato padrão para todas as mensagens de log
        
    Example:
        >>> setup_logging('logs/custom.log', logging.DEBUG)
        >>> logger = logging.getLogger(__name__)
        >>> logger.info("Sistema inicializado")
    """
    import sys
    
    # Cria diretório de logs se não existir
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Configurar handler de arquivo com UTF-8
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Handler customizado para console que lida com emojis
    class EmojiSafeStreamHandler(logging.StreamHandler):
        def emit(self, record):
            try:
                # Tentar emitir normalmente primeiro
                super().emit(record)
            except UnicodeEncodeError:
                try:
                    # Se falhar, remove emojis e tenta novamente
                    original_msg = record.getMessage()
                    record.msg = safe_log_message(original_msg)
                    record.args = ()
                    super().emit(record)
                except Exception:
                    # Último recurso: encoding ASCII
                    record.msg = str(record.msg).encode('ascii', 'ignore').decode('ascii')
                    record.args = ()
                    super().emit(record)
    
    console_handler = EmojiSafeStreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Configurar logger raiz
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Limpar handlers existentes para evitar duplicação
    root_logger.handlers.clear()
    
    # Adicionar handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


def validate_configuration(config):
    """
    Valida se configuração carregada possui todas as seções necessárias.
    
    Executa validação estrutural completa da configuração, verificando:
    - Presença de todas as seções obrigatórias
    - Existência de configurações de portas para monitoramento
    - Formato básico das configurações críticas
    
    Esta validação garante que o sistema pode inicializar corretamente
    sem falhar por configurações ausentes ou malformadas.
    
    Args:
        config (dict): Dicionário de configuração carregado do YAML
        
    Returns:
        bool: True se configuração é válida e completa, False caso contrário
        
    Side Effects:
        - Imprime mensagens de erro específicas para problemas encontrados
        - Ajuda na depuração de problemas de configuração
        
    Example:
        >>> config = load_configuration('config.yaml')
        >>> if validate_configuration(config):
        ...     # Prosseguir com inicialização
        ...     pass
    """
    required_sections = ['detection', 'notifications', 'blocking', 'dashboard']
    
    for section in required_sections:
        if section not in config:
            print(f"❌ Seção obrigatória ausente na configuração: {section}")
            return False
    
    # Valida seção de detecção específica
    if 'ports' not in config['detection']:
        print("❌ Configuração de portas ausente na seção 'detection'")
        return False
    
    # Valida se há pelo menos uma porta configurada
    if not config['detection']['ports']:
        print("❌ Nenhuma porta configurada para monitoramento")
        return False
    
    return True


def format_ip_address(ip_str):
    """
    Formata e valida endereço IPv4 com verificação rigorosa.
    
    Valida formato de endereço IPv4 verificando:
    - Presença de exatamente 4 octetos separados por pontos
    - Cada octeto deve estar no range 0-255
    - Formato numérico válido para cada octeto
    
    Args:
        ip_str (str): String contendo endereço IP para validação
        
    Returns:
        str: Endereço IP formatado se válido, ou None se inválido
        
    Example:
        >>> format_ip_address("192.168.1.1")
        '192.168.1.1'
        >>> format_ip_address("256.1.1.1")
        None
        >>> format_ip_address("invalid.ip")
        None
    """
    try:
        # Validação básica de formato IPv4
        octets = ip_str.split('.')
        if len(octets) != 4:
            return None
            
        for octet in octets:
            if not (0 <= int(octet) <= 255):
                return None
                
        return ip_str
    except (ValueError, AttributeError):
        return None


def get_port_protocol_name(port_number):
    """
    Retorna nome comum do protocolo para portas bem conhecidas.
    
    Mapeia números de porta para nomes de protocolos/serviços padrão
    conforme definido pela IANA. Útil para exibição amigável de
    informações de rede e identificação rápida de serviços.
    
    Args:
        port_number (int): Número da porta (1-65535)
        
    Returns:
        str: Nome do protocolo/serviço, ou 'Unknown' se não mapeado
        
    Example:
        >>> get_port_protocol_name(80)
        'HTTP'
        >>> get_port_protocol_name(443)
        'HTTPS'
        >>> get_port_protocol_name(12345)
        'Unknown'
    """
    common_ports = {
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S'
    }
    
    return common_ports.get(port_number, 'Unknown')


def format_bytes(bytes_count):
    """
    Formata quantidade de bytes em formato legível e amigável.
    
    Converte valores numéricos de bytes para representação em
    unidades maiores (KB, MB, GB, TB) com formatação decimal
    apropriada para exibição ao usuário.
    
    Args:
        bytes_count (int): Quantidade de bytes para formatação
        
    Returns:
        str: String formatada com unidade apropriada
        
    Example:
        >>> format_bytes(1024)
        '1.0 KB'
        >>> format_bytes(1536)
        '1.5 KB'
        >>> format_bytes(1048576)
        '1.0 MB'
    """
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(bytes_count)
    unit_index = 0
    
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    
    return f"{size:.1f} {units[unit_index]}"


def calculate_packets_per_second(packet_count, time_window):
    """
    Calcula taxa de pacotes por segundo para análise de tráfego.
    
    Função utilitária para calcular métricas de rede, especialmente
    útil para detecção de anomalias e comparação com thresholds
    configurados no sistema de detecção DDoS.
    
    Args:
        packet_count (int): Número total de pacotes observados
        time_window (float): Janela de tempo em segundos
        
    Returns:
        float: Taxa de pacotes por segundo, ou 0.0 se time_window <= 0
        
    Example:
        >>> calculate_packets_per_second(100, 10.0)
        10.0
        >>> calculate_packets_per_second(50, 5.0)
        10.0
        >>> calculate_packets_per_second(100, 0)
        0.0
    """
    if time_window <= 0:
        return 0.0
    return packet_count / time_window


def safe_log_message(message):
    """
    Remove emojis de mensagens de log para compatibilidade com Windows.
    
    Remove caracteres emoji Unicode que podem causar erros de codificação
    em terminais Windows que não suportam UTF-8 completo.
    
    Args:
        message (str): Mensagem original com possíveis emojis
        
    Returns:
        str: Mensagem sem emojis, segura para logging
        
    Example:
        >>> safe_log_message("🚀 Sistema iniciado")
        'Sistema iniciado'
        >>> safe_log_message("Erro: ❌ Falha na operação")
        'Erro: Falha na operação'
    """
    import re
    # Remove emojis Unicode usando regex abrangente
    emoji_pattern = re.compile("["
                             u"\U0001F600-\U0001F64F"  # emoticons
                             u"\U0001F300-\U0001F5FF"  # symbols & pictographs
                             u"\U0001F680-\U0001F6FF"  # transport & map symbols
                             u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
                             u"\U00002700-\U000027BF"  # misc symbols
                             u"\U000024C2-\U0001F251"  # misc symbols
                             u"\U0001F900-\U0001F9FF"  # supplemental symbols
                             "]+", flags=re.UNICODE)
    return emoji_pattern.sub('', message).strip()
