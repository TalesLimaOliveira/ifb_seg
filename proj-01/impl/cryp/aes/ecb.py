from cryp.aes.aes import decryption, encryption

AES_BLOCK_SIZE = 16


def ecb_encryption(plain: bytes, key: bytes) -> bytes:
    # Assumption: length of data is multiple of 128 bits
    cipher = []
    for j in range(len(plain) // AES_BLOCK_SIZE):
        p_j = plain[j * AES_BLOCK_SIZE : (j + 1) * AES_BLOCK_SIZE]
        c_j = encryption(p_j, key)
        cipher += c_j
    return bytes(cipher)


def ecb_decryption(cipher: bytes, key: bytes) -> bytes:
    plain = []
    for j in range(len(cipher) // AES_BLOCK_SIZE):
        c_j = cipher[j * AES_BLOCK_SIZE : (j + 1) * AES_BLOCK_SIZE]
        p_j = decryption(c_j, key)
        plain += p_j
    return bytes(plain)


#
# AES_BLOCK_SIZE = 16
#
#
# def pkcs7_pad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
#     pad_len = block_size - (len(data) % block_size)
#     return data + bytes([pad_len] * pad_len)
#
#
# def pkcs7_unpad(data: bytes) -> bytes:
#     pad_len = data[-1]
#     if pad_len < 1 or pad_len > AES_BLOCK_SIZE:
#         raise ValueError("Invalid padding.")
#     if data[-pad_len:] != bytes([pad_len] * pad_len):
#         raise ValueError("Corrupted padding.")
#     return data[:-pad_len]
#
#
# def ecb_encryption(plain: bytes, key: bytes) -> bytes:
#     # Aplica padding antes da encriptação
#     padded_plain = pkcs7_pad(plain)
#     cipher = []
#     for j in range(len(padded_plain) // AES_BLOCK_SIZE):
#         p_j = padded_plain[j * AES_BLOCK_SIZE : (j + 1) * AES_BLOCK_SIZE]
#         c_j = encryption(p_j, key)
#         cipher += c_j
#     return bytes(cipher)
#
#
# def ecb_decryption(cipher: bytes, key: bytes) -> bytes:
#     plain = []
#     for j in range(len(cipher) // AES_BLOCK_SIZE):
#         c_j = cipher[j * AES_BLOCK_SIZE : (j + 1) * AES_BLOCK_SIZE]
#         p_j = decryption(c_j, key)
#         plain += p_j
#     # Remove padding após a decriptação
#     return pkcs7_unpad(bytes(plain))
