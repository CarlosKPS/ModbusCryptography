from mchacha.chacha_operations import *
from mchacha.constants import *


def generate_key_stream(matrix):
    """ :param: The first matrix
        :return: The key stream based on chacha algorithm
    """
    M = matrix
    for i in range(0, 10):
        M = chacha_round(M)

    return M, [key for l in M for key in l]

def initial_key():
    """
    :param m:
    :return: a keystream composed of 3 chacha matrix concatenated
    """
    keystream = ''

    for i in range(0,2):
        generate_key_stream()


def encrypt_decrypt(key=None, nonce=None, vector_plain=VEC_PLAIN_4BIT):
    """
    :param key: is a 256 bit key that going to be use in first matrix
    :param nonce: is constant number you can choice. Default is none and will be use Nonce constants from constants.py
    :param vector_plain: is a set of vector ready to be encrypted of 16 bts
    :return: return a ciphertext encrypted by chacha algorithm
    """
    # just to set some parameters if any of them wasn't set
    if key is None:
        key1 = KEY
    else:
        key1 = key
    if nonce is None:
        n0, n1, n2 = NONCE0, NONCE1, NONCE2
    else:
        n0, n1, n2 = nonce[0], nonce[1], nonce[1]

    counter = '0b' + '0' * 32

    # this two lines create a key stream
    standart_chaca = generate_chacha_matrix(key1, counter, n0, n1, n2, C0, C1, C2, C3, elements=0)
    key_stream = generate_key_stream(standart_chaca)[1]  # key stream ready
    #print(key_stream[0])
    cipher_vec = [vector_plain[0]]
    key_index = 0

    for i in range(1, len(vector_plain)):
        if i % 16 == 0:
            counter = bit_sum(counter, 1)
            key_stream = generate_key_stream(
                generate_chacha_matrix(key1, counter, n0, n1, n2, C0, C1, C2, C3, elements=0)
            )[1]
        current_plain = vector_plain[i-1]
        final_plain = vector_plain[i]
        current_cipher = cipher_vec[i-1]
        current_key = key_stream[(i-1)%16]

        print(current_plain, final_plain, current_cipher, current_key[:6])

        cipher_vec.append(generate_cipher(current_plain, final_plain, current_cipher, current_key,s=[1]))

    #print(counter)
    return cipher_vec


if __name__ == "__main__":
    print("Primeiro vamos ver o plaintext: ")
    print(VEC_PLAIN_4BIT)
    #print([[0,0,0,1],[1,1,0,1]])
    print("\n\nAgora vamos criar o cipher com a função encrypt decrypt:")
    cipher = encrypt_decrypt()
    print(cipher)
    print("\n\nAgora vamos colocar esse cipher de volta no código e verificar se voltamosa ter o plaintext")
    back_to_plain = encrypt_decrypt(vector_plain=cipher)
    print(back_to_plain)