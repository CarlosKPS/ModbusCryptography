# criar a matrix do chacha
from Chacha.binaryfunctions.binoperations import *


def generate_chacha_matrix(key, counter, n0, n1, n2, c0, c1, c2, c3, elements=0):
    try:
        x0 = c0
        x1 = c1
        x2 = c2
        x3 = c3
        x4 = key[:34]
        x5 = '0b' + key[34:66]
        x6 = '0b' + key[66:98]
        x7 = '0b' + key[98:130]
        x8 = '0b' + key[130:162]
        x9 = '0b' + key[162:194]
        x10 = '0b' + key[194:226]
        x11 = '0b' + key[226:]
        x12 = counter
        x13 = n0
        x14 = n1
        x15 = n2
    except:
        raise Exception(" the key has not 256 or some of the inputs are not allowed")

    if elements:
        return [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15]
    else:
        return [[x0, x1, x2, x3], [x4, x5, x6, x7], [x8, x9, x10, x11], [x12, x13, x14, x15]]


def quarter_round(a, b, c, d):
    a = bit_sum(a, b)
    d = xor(d, a)
    d = shift_left(d, 16)
    c = bit_sum(c, d)
    b = xor(b, c)
    b = shift_left(b, 12)
    a = bit_sum(a, b)
    d = xor(d, a)
    d = shift_left(d, 8)
    c = bit_sum(c, d)
    b = xor(b, c)
    b = shift_left(b, 7)

    return a, b, c, d


def chacha_round(matrix):
    M = matrix
    # Column Round
    M[0][0], M[1][0], M[2][0], M[3][0] = quarter_round(M[0][0], M[1][0], M[2][0], M[3][0])
    M[0][1], M[1][1], M[2][1], M[3][1] = quarter_round(M[0][1], M[1][1], M[2][1], M[3][1])
    M[0][2], M[1][2], M[2][2], M[3][2] = quarter_round(M[0][2], M[1][2], M[2][2], M[3][2])
    M[0][3], M[1][3], M[2][3], M[3][3] = quarter_round(M[0][3], M[1][3], M[2][3], M[3][3])
    # Diagonal Round
    M[0][0], M[1][1], M[2][2], M[3][3] = quarter_round(M[0][0], M[1][1], M[2][2], M[3][3])
    M[0][1], M[1][2], M[2][3], M[3][0] = quarter_round(M[0][1], M[1][2], M[2][3], M[3][0])
    M[0][2], M[1][3], M[2][0], M[3][1] = quarter_round(M[0][2], M[1][3], M[2][0], M[3][1])
    M[0][3], M[1][0], M[2][1], M[3][2] = quarter_round(M[0][3], M[1][0], M[2][1], M[3][2])

    return M


def generate_cipher(pa, pf, ca, xa, s=[]):
    # primeiro realizar o xor entre o plaintext atual e o proximo
    # S=[]: criptografa inclusive o evento 0
    # S=[e1,e2,e3,..,en]=Gamma_pa: exclui o evento

    p_atual = '0b' + ''.join(map(str, pa))
    p_final = '0b' + ''.join(map(str, pf))

    c_atual = '0b' + ''.join(map(str, ca))
    xf = xa

    e = xor(p_atual, p_final)

    if not (int(e, 2)):
        # print("Não houve alteração do plaintext")
        if (s):
            cf = c_atual
            # print("não criptografou o evento nulo")
            # print("cf = c_atual = ", cf)
        else:
            # print("criptografando o evento nulo")
            if len(xa[2:]) > len(pa):
                xf = xa[:2 + len(pa)]
                # print("xa é maior do que o tamanho de pa xf =", xf)

            ec = xor(e, xa)
            cf = xor(c_atual, ec)
            # print("ec {} and cf {}".format(ec, cf))

    else:
        # print("Houve alteração no plaintext")
        # if somente para pegar o pedaço da chave de interesse
        if len(xa[2:]) > len(pa):
            xf = xa[:2 + len(pa)]
            # print('xa é maior do que o tamanho de pa xf = ', xf)

        # enquanto xf for algum evento dentro de s=GAMMMA executa o comando abaixo
        while xf in s:
            # print("entrou no loop")
            xa = '0b' + xa[2 + len(pa):]  # mudamos xa ( excluimos os 4 primeiros valores após 0b
            xf = xa[:2 + len(pa)]  # atribuimos a xf o novo xa
            # print(xf)

        ec = xor(e, xf)
        cf = xor(c_atual, ec)
        # print("ec {} and cf {}".format(ec, cf))

    # pega somente os ultimos 4 termos
    return list(map(int, cf[-len(pa):]))
    # return '0b' + cf[-len(pa):], list(map(int, cf[-len(pa):])), xa, xf

def event_cd(u0, u1, k, ep=None,en=None,cd=True):
    """
    Return the events of the process of encrypt and decrypt
    :param u0:-> previous reding
    :param u1:-> current reading
    :param k:-> current key part
    :param ep:-> forbidden event
    :param en:-> null event
    :param cd:-> choose encryption or decryption mode: default = True (encryption mode)
    :return: Event in a list
    """

    if en is None:
        en = [0]*len(u0)
    if ep is None:
        ep = [1]*len(u0)

    # change en and ep if the process is decryption
    if not cd:
        aux = ep
        ep = en
        en = aux
    print("u0: ", u0)
    print("u1: ", u1)
    # If don't have any change among events then return a list of zeros
    if u1==u0:
        print("pa e pf são iguais")
        return [0]*len(u0)

    print("A chave é: ", k)
    # creating entry event
    e0 = [i^j for i,j in zip(u0,u1)]
    #print("Evento de entrada: ", e0)
    # Creating out  event
    e1 = [m^n for m,n in zip(e0,k)]
    print("evento de saida: ", e1)
    if e1 == en:
        print("evento cifrado é igual ao evento nulo")
        print("xor(ep,k):", [a^b for a,b in zip(ep,k)])
        return [a^b for a,b in zip(ep,k)]
    else:
        #print("evento de saida: ", e1)
        return e1