"""Ceaser Cipher"""


def encrypt(message: str, shift: int = 0) -> str:
    """Encrypt using Caesar Cipher.

    shift must be between -25 and 25.
    """
    encrypted = ""
    if not -25 <= shift <= 25:
        raise ValueError("Invalid shift value.")

    for c in message:
        if c.isalpha():
            start = ord("a") if c.islower() else ord("A")
            shifted_c = chr((ord(c) - start + shift) % 26 + start)
        else:
            shifted_c = c
        encrypted += shifted_c

    return encrypted


def decrypt(message: str, shift: int = 0) -> str:
    """Decrypt using Caesar Cipher.

    shift must be between -25 and 25.
    negative shifts are normalized.
    """
    return encrypt(message, -abs(shift))


def brute_force(message: str) -> list[str]:
    """Brute Force

    apply 26 possible shifts.
    """
    all_results: list[str] = []
    for shift_value in range(26):
        all_results.append(decrypt(message, shift_value))

    return all_results
