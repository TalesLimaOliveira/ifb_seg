import pytest

from cryp.caeser.cipher import brute_force, decrypt, encrypt


def test_positive_caeser_cipher_encrypt_message_lower():
    message = "hello world"
    shift = 4
    expected = "lipps asvph"
    result = encrypt(message, shift)

    assert result == expected


def test_positive_caeser_cipher_encrypt_message_upper():
    message = "HELLO WORLD"
    shift = 4
    expected = "LIPPS ASVPH"
    result = encrypt(message, shift)

    assert result == expected


def test_positive_caeser_cipher_encrypt_message_mix_upper_and_lower():
    message = "Hello World"
    shift = 4
    expected = "Lipps Asvph"
    result = encrypt(message, shift)

    assert result == expected


def test_positive_caeser_cipher_encrypt_simple_message():
    message = "Yet another implementation of Caeser Cipher in PYTHON!"
    shift = 13
    expected = "Lrg nabgure vzcyrzragngvba bs Pnrfre Pvcure va CLGUBA!"
    result = encrypt(message, shift)

    assert result == expected


def test_positive_caeser_cipher_encrypt_shift_zero():
    message = "Hello World"
    shift = 0
    expected = "Hello World"
    result = encrypt(message, shift)

    assert result == expected


def test_negative_caeser_cipher_encrypt_shift_negative_value():
    message = "Hello World"
    shift = -26
    with pytest.raises(ValueError):
        _ = encrypt(message, shift)


def test_negative_caeser_cipher_encrypt_shift_27_value():
    message = "Hello World"
    shift = 27
    with pytest.raises(ValueError):
        _ = encrypt(message, shift)


def test_positive_caeser_cipher_decrypt_shift_positive_value():
    message = "Kvjk Dvjjrxv!"
    shift = 17
    expected = "Test Message!"
    result = decrypt(message, shift)

    assert result == expected


def test_positive_caeser_cipher_decrypt_shift_negative_value():
    message = "Kvjk Dvjjrxv!"
    shift = -17
    expected = "Test Message!"
    result = decrypt(message, shift)

    assert result == expected


def test_negative_caeser_cipher_decrypted_shift_invalid_value():
    message = "Yet another test"
    shift = -30
    with pytest.raises(ValueError):
        _ = encrypt(message, shift)


def test_positive_caeser_cipher_decrypt_message_lower():
    message = "zrffntr vf gbb ybbbbbbbat"
    shift = 13
    expected = "message is too looooooong"
    result = decrypt(message, shift)

    assert result == expected


def test_positive_caeser_cipher_decrypt_simple_message():
    message = "Lrg nabgure vzcyrzragngvba bs Pnrfre Pvcure va CLGUBA!"
    shift = 13
    expected = "Yet another implementation of Caeser Cipher in PYTHON!"
    result = decrypt(message, shift)

    assert result == expected


def test_brute_force_all_shift():
    message = "test message"
    result = brute_force(message)

    assert len(result) == 26


def test_brute_force_find_message_decrypted():
    message = "qefp fp x pfjmib jbppxdb"
    # this is a simple message
    expected = decrypt(message)
    result = brute_force(message)

    assert expected in result
