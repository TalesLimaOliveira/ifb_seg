import yaml 
import logging 
import os 
from pathlib import Path 


def load_configuration(config_file='config.yaml'):
    try:
        # Converte para objeto Path para melhor manipulação
        config_path = Path(config_file)
        # Verifica se arquivo existe
        if not config_path.exists():
            print(f"❌ Arquivo de configuração não encontrado: {config_file}")
            return None
            
        # Abre arquivo com encoding UTF-8 e carrega YAML
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            print(f"✅ Configurações carregadas de: {config_file}")
            return config
            
    except yaml.YAMLError as e:
        # Trata erros específicos de formato YAML
        print(f"❌ Erro ao processar arquivo YAML: {e}")
        return None
    except Exception as e:
        # Trata qualquer outro erro inesperado
        print(f"❌ Erro inesperado ao carregar configurações: {e}")
        return None


def setup_logging(log_file='logs/ddos_system.log', level=logging.INFO):
    import sys
    
    # Cria diretório de logs se não existir
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Configura handler para salvar logs em arquivo
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Classe customizada para tratar problemas de encoding no console
    class EmojiSafeStreamHandler(logging.StreamHandler):
        def emit(self, record):
            try:
                # Tenta emitir mensagem normalmente
                super().emit(record)
            except UnicodeEncodeError:
                try:
                    # Se falhar, remove emojis e tenta novamente
                    original_msg = record.getMessage()
                    record.msg = safe_log_message(original_msg)
                    record.args = ()
                    super().emit(record)
                except Exception:
                    # Último recurso: converte para ASCII
                    record.msg = str(record.msg).encode('ascii', 'ignore').decode('ascii')
                    record.args = ()
                    super().emit(record)
    
    # Configura handler para exibir logs no console
    console_handler = EmojiSafeStreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Configura logger raiz (global)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove handlers existentes para evitar duplicação
    root_logger.handlers.clear()
    
    # Adiciona os handlers configurados
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


def validate_configuration(config):
    # Lista de seções obrigatórias no arquivo de configuração
    required_sections = ['detection', 'notifications', 'blocking', 'dashboard']
    
    # Verifica se todas as seções obrigatórias estão presentes
    for section in required_sections:
        if section not in config:
            print(f"❌ Seção obrigatória ausente na configuração: {section}")
            return False
    
    # Verifica se seção 'detection' tem configuração de 'ports'
    if 'ports' not in config['detection']:
        print("❌ Configuração de portas ausente na seção 'detection'")
        return False
    
    # Verifica se pelo menos uma porta está configurada
    if not config['detection']['ports']:
        print("❌ Nenhuma porta configurada para monitoramento")
        return False
    
    return True  # Todas as validações passaram


def format_ip_address(ip_str):
    try:
        # Divide IP em octetos separados por ponto
        octets = ip_str.split('.')
        # Deve ter exatamente 4 octetos
        if len(octets) != 4:
            return None
            
        # Cada octeto deve estar entre 0-255
        for octet in octets:
            if not (0 <= int(octet) <= 255):
                return None
                
        return ip_str  # IP válido
    except (ValueError, AttributeError):
        # Trata erros de conversão ou strings inválidas
        return None


def get_port_protocol_name(port_number):
    # Dicionário com mapeamento de portas conhecidas
    common_ports = {
        22: 'SSH',      # Secure Shell
        23: 'Telnet',   # Terminal remoto
        25: 'SMTP',     # Email (envio)
        53: 'DNS',      # Domain Name System
        80: 'HTTP',     # Web não-seguro
        110: 'POP3',    # Email (recebimento)
        143: 'IMAP',    # Email (recebimento)
        443: 'HTTPS',   # Web seguro
        993: 'IMAPS',   # IMAP seguro
        995: 'POP3S'    # POP3 seguro
    }
    
    # Retorna nome do protocolo ou 'Unknown' se não encontrado
    return common_ports.get(port_number, 'Unknown')


def format_bytes(bytes_count):
    # Lista de unidades em ordem crescente
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(bytes_count)
    unit_index = 0
    
    # Divide por 1024 até encontrar unidade apropriada
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    
    # Retorna formatado com 1 casa decimal
    return f"{size:.1f} {units[unit_index]}"


def calculate_packets_per_second(packet_count, time_window):
    # Evita divisão por zero
    if time_window <= 0:
        return 0.0
    # Calcula taxa: pacotes / tempo
    return packet_count / time_window


def safe_log_message(message):
    import re
    # Padrão regex para detectar emojis Unicode
    emoji_pattern = re.compile("["
                             u"\U0001F600-\U0001F64F"  # emoticons
                             u"\U0001F300-\U0001F5FF"  # symbols & pictographs
                             u"\U0001F680-\U0001F6FF"  # transport & map symbols
                             u"\U0001F1E0-\U0001F1FF"  # flags (iOS)
                             u"\U00002700-\U000027BF"  # misc symbols
                             u"\U000024C2-\U0001F251"  # misc symbols
                             u"\U0001F900-\U0001F9FF"  # supplemental symbols
                             "]+", flags=re.UNICODE)
    # Remove emojis e limpa espaços extras
    return emoji_pattern.sub('', message).strip()
