import logging
import os
import re
import yaml
from pathlib import Path


def load_configuration(config_file='config.yaml'):
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
    import sys
    
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    class EmojiSafeStreamHandler(logging.StreamHandler):
        def emit(self, record):
            try:
                super().emit(record)
            except UnicodeEncodeError:
                try:
                    original_msg = record.getMessage()
                    record.msg = safe_log_message(original_msg)
                    record.args = ()
                    super().emit(record)
                except Exception:
                    record.msg = str(record.msg).encode('ascii', 'ignore').decode('ascii')
                    record.args = ()
                    super().emit(record)
    
    console_handler = EmojiSafeStreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


def validate_configuration(config):
    required_sections = ['detection', 'notifications', 'blocking', 'dashboard']
    
    for section in required_sections:
        if section not in config:
            print(f"❌ Seção obrigatória ausente na configuração: {section}")
            return False
    
    if 'ports' not in config['detection']:
        print("❌ Configuração de portas ausente na seção 'detection'")
        return False
    
    if not config['detection']['ports']:
        print("❌ Nenhuma porta configurada para monitoramento")
        return False
    
    return True


def safe_log_message(message):
    emoji_pattern = re.compile("["
                             u"\U0001F600-\U0001F64F"
                             u"\U0001F300-\U0001F5FF"
                             u"\U0001F680-\U0001F6FF"
                             u"\U0001F1E0-\U0001F1FF"
                             u"\U00002700-\U000027BF"
                             u"\U000024C2-\U0001F251"
                             u"\U0001F900-\U0001F9FF"
                             "]+", flags=re.UNICODE)
    return emoji_pattern.sub('', message).strip()
