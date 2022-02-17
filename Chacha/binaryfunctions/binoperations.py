######################################################################################################################
# Binary oparations particulary made to use in chacha algorihtm ######################################################
# Made by: Carlos Keleanderson Pereira da Silva ######################################################################
# Federal University of Rio de Janeiro ###############################################################################
######################################################################################################################

import random


def generate_key(n_bits):
    """This function return a key of n_bits bit"""
    number = ''  # aux vector to save all bits

    # Generates all key's bits
    for i in range(0, n_bits):
        number = number + str(random.randrange(0, 2))
    return '0b' + number


def shift_left(number, shift):
    """The function receive a binary number such as a=bin(12) and compute a left shift in this number by the value
    of a shift parameter.
    number: an integer number
    shift: number of bits shifted to the left
    """
    n = number
    n1 = '0b' + n[2 + shift:] + n[2:2 + shift]

    if len(n1) == 34:
        return n1
    else:
        diff = abs(len(n1) - 34)
        return '0b' + '0' * diff + n1[2:]


def xor(n1, n2):
    if type(n1) is str:
        n1 = int(n1, 2)
    else:
        n1 = n1
    if type(n2) is str:
        n2 = int(n2, 2)
    else:
        n2 = n2

    number = bin(n1 ^ n2)

    # print("numero binario e tamanho ")
    # print(number, len(number))
    # print("n1 e n2")
    # print(n1,n2)

    if len(number) == 34:
        return number
    else:
        diff = abs(len(number) - 34)
        return '0b' + '0' * diff + number[2:]


def bit_sum(n1, n2,l=32):
    # verifiying if is a bit class
    if type(n1) is str:
        n1 = n1
    else:
        n1 = bin(n1)
    if type(n2) is str:
        n2 = n2
    else:
        n2 = bin(n2)

    number = bin(int(n1, 2) + int(n2, 2))

    if len(number[2:]) == l:
        return number
    elif len(number[2:]) < l:
        diff = l - len(number[2:])
        return '0b' + '0' * diff + number[2:]
    else:
        return '0b' + number[len(number) - 32:]
