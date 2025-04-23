"""Implementation of ADVANCED ENCRYPTION STANDARD (AES)

Docs:
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
- https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
"""

import os

from cryp.aes.constants import AES_S_BOX, INV_S_BOX, RCON_TABLE


def xtime(a: int) -> int:
    """Multply by x,  GF(2^8)"""
    if a & 0x80:
        return ((a << 1) ^ 0x1B) & 0xFF
    return a << 1


def mix_column(col: list[int]):
    c_0 = col[0]
    all_xor = col[0] ^ col[1] ^ col[2] ^ col[3]
    col[0] ^= all_xor ^ xtime(col[0] ^ col[1])
    col[1] ^= all_xor ^ xtime(col[1] ^ col[2])
    col[2] ^= all_xor ^ xtime(col[2] ^ col[3])
    col[3] ^= all_xor ^ xtime(c_0 ^ col[3])


def mix_columns(state: list[list[int]]):
    """The MixColumns() transformation operates on the State `column-by-column`, treating each
    column as a four-term polynomial as described in Sec. 4.3. The columns are considered as
    polynomials over GF(28) and multiplied modulo x4 + 1 with a fixed polynomial a(x), given by
    a(x) = {03}x3 + {01}x2 + {01}x + {02} .

    Ref: 5.1.3
    """
    for col in state:
        mix_column(col)


def shift_rows(state: list[list[int]]) -> list[list[int]]:
    """In the ShiftRows() transformation, the bytes in the last three rows of the State are cyclically
    shifted over different numbers of bytes (offsets). The first row, r = 0, is not shifted.

    Example::
        Input:
            state = [
                [00, 10, 20, 30],
                [01, 11, 21, 31],
                [02, 12, 22, 32],
                [03, 13, 23, 33],
            ]
        Ouput:
            [
                [00, 10, 20, 30],
                [11, 21, 31, 01],
                [22, 32, 02, 12],
                [33, 03, 13, 23],
            ]
    Ref: 5.1.2
    """
    state[0][1], state[1][1], state[2][1], state[3][1] = (
        state[1][1],
        state[2][1],
        state[3][1],
        state[0][1],
    )
    state[0][2], state[1][2], state[2][2], state[3][2] = (
        state[2][2],
        state[3][2],
        state[0][2],
        state[1][2],
    )
    state[0][3], state[1][3], state[2][3], state[3][3] = (
        state[3][3],
        state[0][3],
        state[1][3],
        state[2][3],
    )

    return state


def sub_bytes(state: list[list[int]]):
    """The SubBytes() transformation is a non-linear byte substitution that operates independently
    on each byte of the State using a substitution table (S-box)

    For example, if s1,1 = {53}, then the substitution value would be determined by the intersection
    of the row with index ‘5’ and the column with index ‘3’ in Fig. 7. This would result in s1 having
    a value of {ed}.

    Ref: 5.1.1
    """
    for row in range(len(state)):
        state[row] = [
            AES_S_BOX[state[row][column]] for column in range(len(state[0]))
        ]


def add_round_key(
    state: list[list[int]], key_schedule: list[list[list[int]]], round: int
):
    """In the add_round_key() transformation, a Round Key is added to the State by a simple bitwise XOR operation (^).

    Ref: 5.1.4"""
    round_key = key_schedule[round]
    for row in range(len(state)):
        state[row] = [
            state[row][column] ^ round_key[row][column]
            for column in range(len(state[0]))
        ]


def xor_bytes(input_a: bytes, input_b: bytes) -> bytes:
    """XOR with Bytes"""
    return bytes([x ^ y for (x, y) in zip(input_a, input_b)])


def sub_word(word: list[int]) -> bytes:
    """SubWord() is a function that takes a four-byte input word and applies the S-box (Sec. 5.1.1, Fig. 7)
    to each of the four bytes to produce an output word.

    Ref: 5.2"""
    substituted_word = bytes(AES_S_BOX[i] for i in word)
    return substituted_word


def rot_word(word: list[int]) -> list[int]:
    """The function RotWord() takes a word [a0 ,a1 ,a2 ,a3] as input,
    performs a cyclic permutation, and returns the word [a1 ,a2 ,a3 ,a0].

    Example::
        Input: [1, 2, 3, 4]

        Output: [2, 3, 4, 1]

    Args:
        word list[int]: A list of integers

    Returns:
        list[int]: A list of integers with the first and last elements swapped
    """
    return word[1:] + word[:1]


def rcon(value: int) -> bytes:
    """The round constant word array, Rcon[i], contains the values given by [xi-1,{00},{00},{00}], with x i-1
    being powers of x (x is denoted as {02}) in the field GF(28), as discussed in Sec. 4.2 (note that i starts at 1, not 0).

    RCON Tabe
    Ref:
        5.2
        https://www.lncc.br/~borges/doc/O%20algoritmo%20AES%20Apresentacao%20e%20Descricao%20da%20Estrura.pdf
    """
    #                  [xi-1,{00},{00},{00}]
    rcon_value = bytes([RCON_TABLE[value - 1], 0, 0, 0])
    return rcon_value


def key_expansion(key: bytes, number_bytes: int = 4) -> list[list[list[int]]]:
    """The AES algorithm takes the Cipher Key, K, and performs a Key Expansion routine to generate a
    key schedule.

    This function need another functions:
    - SubWord() !segundo
    - RotWord() !terceiro
    - Rcon() !ultimo
    - XorBytes() [Not explicit, but require a lot xor operations!] !primeiro

    Ref: 5.2
    https://www.ime.usp.br/~rt/cranalysis/AESSimplifiedBerent.pdf
    """
    number_keys = len(key) // 4
    key_bit_length = len(key) * 8

    number_rounds = {
        128: 10,
        192: 12,
        256: 14,
    }[key_bit_length]

    # The resulting key schedule consists of a linear array of 4-byte words,
    # denoted [wi], with i in the range 0 <= i < Nb(Nr + 1).
    w = bytes_to_state(key)

    for i in range(number_keys, number_bytes * (number_rounds + 1)):
        temp = w[i - 1]
        if i % number_keys == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), rcon(i // number_keys))
        elif number_keys > 6 and i % number_keys == 4:
            temp = sub_word(temp)
        # LINTER Error! bytes assigned to list[int]
        w.append(xor_bytes(w[i - number_keys], temp))

    return [w[i * 4 : (i + 1) * 4] for i in range(len(w) // 4)]


def state_to_bytes(state: list[list[int]]) -> bytes:
    """Convert 'state' to 'bytes'"""
    cipher = bytes(state[0] + state[1] + state[2] + state[3])
    return cipher


def bytes_to_state(data: bytes) -> list[list[int]]:
    """Convert 'bytes' to 'state' matrix (4x4), using column-major order.

    Example::
        Input: bytes(range(16))

        Output:
            [
                [0, 4,  8, 12],
                [1, 5,  9, 13],
                [2, 6, 10, 14],
                [3, 7, 11, 15],
            ]

    Args:
        data (bytes): A 16-byte input block

    Returns:
        list[list[int]]: A 4x4 matrix representing the AES state

    What occuring inside this function?
        Bytes: [ 0,  1,  2,  3,
                 4,  5,  6,  7,
                 8,  9, 10, 11,
                12, 13, 14, 15 ]
        - `row` goes from 0 to 3, representing the row of the matrix
        - `column` goes from 0 to 3, representing the column of the matrix
        - `data[row + 4 * column]` accesses the correct element in the linear sequence for the position (row, column)
        example:
        For row=0, column=0: data[0 + 4 * 0] = data[0]
        For row=1, column=0: data[1 + 4 * 0] = data[1]
        For row=0, column=1: data[0 + 4 * 1] = data[4]
        For row=2, column=2: data[2 + 4 * 2] = data[10]
        ...
        Thus, transforming the rows into columns
    """
    state = [data[i * 4 : (i + 1) * 4] for i in range(len(data) // 4)]
    return state


def encryption(data: bytes, key: bytes) -> bytes:
    key_bit_length = len(key) * 8
    number_rounds = {
        128: 10,
        192: 12,
        256: 14,
    }[key_bit_length]

    state = bytes_to_state(data)

    key_schedule = key_expansion(key)

    add_round_key(state, key_schedule, round=0)

    for round in range(1, number_rounds):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, round=number_rounds)

    out = state_to_bytes(state)
    return out


def inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    # [00, 10, 20, 30]     [00, 10, 20, 30]
    # [01, 11, 21, 31] <-- [11, 21, 31, 01]
    # [02, 12, 22, 32]     [22, 32, 02, 12]
    # [03, 13, 23, 33]     [33, 03, 13, 23]
    state[1][1], state[2][1], state[3][1], state[0][1] = (
        state[0][1],
        state[1][1],
        state[2][1],
        state[3][1],
    )
    state[2][2], state[3][2], state[0][2], state[1][2] = (
        state[0][2],
        state[1][2],
        state[2][2],
        state[3][2],
    )
    state[3][3], state[0][3], state[1][3], state[2][3] = (
        state[0][3],
        state[1][3],
        state[2][3],
        state[3][3],
    )


def inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
    for row in range(len(state)):
        state[row] = [
            INV_S_BOX[state[row][column]] for column in range(len(state[0]))
        ]


def xtimes_0e(b):
    # 0x0e = 14 = b1110 = ((x * 2 + x) * 2 + x) * 2
    return xtime(xtime(xtime(b) ^ b) ^ b)


def xtimes_0b(b):
    # 0x0b = 11 = b1011 = ((x*2)*2+x)*2+x
    return xtime(xtime(xtime(b)) ^ b) ^ b


def xtimes_0d(b):
    # 0x0d = 13 = b1101 = ((x*2+x)*2)*2+x
    return xtime(xtime(xtime(b) ^ b)) ^ b


def xtimes_09(b):
    # 0x09 = 9  = b1001 = ((x*2)*2)*2+x
    return xtime(xtime(xtime(b))) ^ b


def inv_mix_column(col: list[int]):
    c_0, c_1, c_2, c_3 = col[0], col[1], col[2], col[3]
    col[0] = xtimes_0e(c_0) ^ xtimes_0b(c_1) ^ xtimes_0d(c_2) ^ xtimes_09(c_3)
    col[1] = xtimes_09(c_0) ^ xtimes_0e(c_1) ^ xtimes_0b(c_2) ^ xtimes_0d(c_3)
    col[2] = xtimes_0d(c_0) ^ xtimes_09(c_1) ^ xtimes_0e(c_2) ^ xtimes_0b(c_3)
    col[3] = xtimes_0b(c_0) ^ xtimes_0d(c_1) ^ xtimes_09(c_2) ^ xtimes_0e(c_3)


def inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    for row in state:
        inv_mix_column(row)


def decryption(cipher: bytes, key: bytes) -> bytes:
    key_bit_length = len(key) * 8
    number_rounds = {
        128: 10,
        192: 12,
        256: 14,
    }[key_bit_length]

    number_keys = key_bit_length // 4

    state = bytes_to_state(cipher)

    key_schedule = key_expansion(key)

    add_round_key(state, key_schedule, round=number_rounds)

    for round in range(number_rounds - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule, round)
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule, round=0)

    plain = state_to_bytes(state)
    return plain


def generate_aes_key(key_size: int = 16) -> bytes:
    """AES key for 128, 192 or 256 bytes."""
    if key_size not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes long.")
    return os.urandom(key_size)
