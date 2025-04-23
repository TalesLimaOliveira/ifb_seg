import pytest

from cryp.aes.aes import (
    decryption,
    encryption,
    generate_aes_key,
    rcon,
    rot_word,
    shift_rows,
    xor_bytes,
)
from cryp.aes.ecb import ecb_decryption, ecb_encryption


def test_aes_bytes_to_state():
    pass


def test_aes_state_to_bytes():
    pass


def test_aes_xor_bytes():
    bytes_1 = b"\x10\x20\x30\x40"
    bytes_2 = b"\x05\x15\x25\x35"
    expected = b"\x15\x35\x15\x75"
    result = xor_bytes(bytes_1, bytes_2)

    assert result == expected


def test_aes_sub_word():
    pass


def test_aes_rot_word():
    words = [1, 2, 3, 4]
    expected = [2, 3, 4, 1]
    result = rot_word(words)

    assert result == expected


def test_aes_rcon():
    value = 10
    expected = b"6\x00\x00\x00"
    result = rcon(value)

    assert result == expected


def test_aes_rcon_out_of_range():
    value = 12
    with pytest.raises(IndexError):
        _ = rcon(value)


def test_aes_shift_rows():
    state = [
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        [9, 10, 11, 12],
        [13, 14, 15, 16],
    ]

    expected = [
        [1, 6, 11, 16],
        [5, 10, 15, 4],
        [9, 14, 3, 8],
        [13, 2, 7, 12],
    ]

    result = shift_rows(state)

    assert result == expected


def test_aes_encrytion_cipher_nist_01_aes_128():
    plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
    key = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")
    expected_ciphertext = bytearray.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    ciphertext = encryption(bytes(plaintext), bytes(key))

    assert ciphertext == expected_ciphertext


def test_aes_encrytion_cipher_nist_02_aes_256():
    plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
    key = bytearray.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    expected_ciphertext = bytearray.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
    ciphertext = encryption(bytes(plaintext), bytes(key))

    assert ciphertext == expected_ciphertext


def test_aes_encrytion_cipher_nist_03_aes_192():
    plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
    key = bytearray.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    expected_ciphertext = bytearray.fromhex("8ea2b7ca516745bfeafc49904b496089")
    ciphertext = encryption(bytes(plaintext), bytes(key))

    assert ciphertext == expected_ciphertext


def test_aes_decrytion_cipher_nist_01_aes_128():
    plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
    key = bytearray.fromhex("000102030405060708090a0b0c0d0e0f")

    encrypted_plaintext = bytearray.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    decrypted_plaintext = decryption(encrypted_plaintext, key)

    assert decrypted_plaintext == plaintext


def test_aes_decrytion_cipher_nist_02_aes_192():
    plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
    key = bytearray.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")

    encrypted_plaintext = bytearray.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
    decrypted_plaintext = decryption(encrypted_plaintext, key)

    assert decrypted_plaintext == plaintext


def test_aes_decrytion_cipher_nist_03_aes_256():
    plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
    key = bytearray.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )

    encrypted_plaintext = bytearray.fromhex("8ea2b7ca516745bfeafc49904b496089")
    decrypted_plaintext = decryption(encrypted_plaintext, key)

    assert decrypted_plaintext == plaintext


def test_aes_ecb_encryption_decryption():
    plaintext = bytearray.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )

    key = bytearray.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

    expected_ciphertext = bytearray.fromhex(
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4"
    )

    ciphertext = ecb_encryption(plaintext, key)
    assert ciphertext == expected_ciphertext

    recovered_plaintext = ecb_decryption(ciphertext, key)
    assert recovered_plaintext == plaintext


def test_aes_ecb_encryption_decryption_with_custom_message():
    message = "Thats my Kung Fu"
    key = b"\x18\xa1\x7fT\xf1'\x11\x04\x1a\xfe\xe5\xb4\x95\xa1\xf3\xd0"

    plaintext_bytes = message.encode("utf-8")
    encrypted_plaintext = ecb_encryption(plaintext_bytes, key)

    decrypted_bytes = ecb_decryption(encrypted_plaintext, key)
    decrypted_plaintext = decrypted_bytes[: len(plaintext_bytes)].decode(
        "utf-8"
    )

    assert decrypted_plaintext == message


def test_aes_ecb_encryption_decryption_example_colab():
    message = "mensagem secreta"
    key = b"IQubQ\x08\xa9}\xcf\xa8}\xc9\xd1\x8d\xdeW"

    plaintext_bytes = message.encode("utf-8")
    encrypted_plaintext = ecb_encryption(plaintext_bytes, key)

    decrypted_bytes = ecb_decryption(encrypted_plaintext, key)
    # Remove padding
    decrypted_plaintext = decrypted_bytes[: len(plaintext_bytes)].decode(
        "utf-8"
    )

    assert decrypted_plaintext == message


def test_aes_ecb_encryption_decryption_exemple_colab_decrypt():
    message = "mensagem secreta"
    key = b"!\x9b\x12\\5\xe4\xc8\x03n\x15\xcf><Q\x19\xda"

    encrypted_message = b"\xc8\x05 fOXV$\x93sl\xb7\xbe\x88\xaf\xb7p\x18?\x11,\xa8\x958_\x00\xd7\xb0\xaa\xd6p\xa9"

    decrypted_bytes = ecb_decryption(encrypted_message, key)
    decrypted_plaintext = decrypted_bytes[: len(message)].decode("utf-8")

    assert decrypted_plaintext == message


def test_aes_ecb_encryption_decryption_with_generate_key():
    message = "this is my message"
    key = generate_aes_key(16)  # AES-128

    plaintext_bytes = message.encode("utf-8")

    # Adding Padding
    padding_len = 16 - (len(plaintext_bytes) % 16)
    plaintext_bytes_padded = plaintext_bytes + bytes([0] * padding_len)

    encrypted_plaintext = ecb_encryption(plaintext_bytes_padded, key)

    decrypted_bytes = ecb_decryption(encrypted_plaintext, key)
    # Remove padding
    decrypted_plaintext = decrypted_bytes[: len(plaintext_bytes)].decode(
        "utf-8"
    )

    assert decrypted_plaintext == message
