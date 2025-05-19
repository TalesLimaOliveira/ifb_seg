from Crypto.Cipher import DES, AES
from Crypto.PublicKey import RSA

def pad(text, block_size):
    """Adds padding to the text to make its length a multiple of block_size."""
    padding_len = block_size - len(text) % block_size
    return text + chr(padding_len) * padding_len

def unpad(text):
    """Removes padding from the text."""
    padding_len = ord(text[-1])
    return text[:-padding_len]

def encrypt_des(text, key):
    """Encrypts the given text using DES encryption with the provided key."""
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(text, 8)
    encrypted = cipher.encrypt(padded_text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_des(cipher_text, key):
    """Decrypts the given cipher text using DES decryption with the provided key."""
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(cipher_text)).decode()
    return unpad(decrypted)

def encrypt_aes(text, key):
    """Encrypts the given text using AES encryption with the provided key."""
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(text, 16)
    encrypted = cipher.encrypt(padded_text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_aes(cipher_text, key):
    """Decrypts the given cipher text using AES decryption with the provided key."""
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(cipher_text)).decode()
    return unpad(decrypted)

def generate_rsa_keys():
    """Generates a pair of RSA keys (private and public)."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(text, public_key_str):
    """Encrypts the given text using RSA encryption with the provided public key."""
    public_key = RSA.import_key(public_key_str)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_rsa(cipher_text, private_key_str):
    """Decrypts the given cipher text using RSA decryption with the provided private key."""
    private_key = RSA.import_key(private_key_str)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(cipher_text))
    return decrypted.decode()