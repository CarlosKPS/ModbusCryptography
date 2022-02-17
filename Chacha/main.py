from mchacha.chacha_operations import *
from mchacha.constants import *


# COLOCAR UMA CONDICAO PARA EVITAR EVENTO PROIBIDO
def generate_random_plain(bits, n_vec):
    vec_text = open('vec.txt', 'w')
    for i in range(0, n_vec):
        vec_text.write(str(random_vector(bits)) + '\n')
    vec_text.close()
    return 0


def random_vector(n_bits):
    vector = ''
    for i in range(0, n_bits):
        vector = vector + str(random.randrange(0, 2)) + ' '
    return vector.strip(" ")


def read_vect(filename):
    f = open(filename + '.txt', 'r')
    vector = []
    for line in f:
        vector.append([int(i) for i in line.split()])
    return vector


def record_vec_in_file(vector, filename=None):
    if filename is None:
        name = 'new_vec_text'
    else:
        name = filename
    f = open(name + '.txt', 'w')
    for i in vector:
        f.write(' '.join(map(str, i)) + '\n')


def generate_key_stream(matrix):
    """ :param: The first matrix
        :return: The key stream based on chacha algorithm
    """
    M = matrix
    for i in range(0, 10):
        M = chacha_round(M)

    return M, [key for l in M for key in l]


def my_join(x):
    """
    :param x: -> the list desired to join
    :return:
    """
    return ''.join(x)


def counter_update(counter):
    c = counter
    add = bin(int(c, 2) + 1)
    diff = abs(len(add) - 34)
    c = '0b' + '0' * diff + add[2:]
    return c


# Funcionando
def generate_initial_keystream(key=None, nonce=None):
    """
    :param key:
    :param nonce:
    :return: The initial keystream
    """

    # verifying if key is None
    if key is None:
        if key is None:
            key1 = KEY
        else:
            key1 = key

    # verifiying if nonce is None
    if nonce is None:
        n0, n1, n2 = NONCE0, NONCE1, NONCE2
    else:
        n0, n1, n2 = nonce[0], nonce[1], nonce[1]

    # setting counter
    local_counter = '0b' + '0' * 32  # pensar em colocar ou não como parâmetro global
    # keystream variable
    keystream = ''

    for i in range(0, 3):
        # generate initial matrix
        m_1 = generate_chacha_matrix(key1, local_counter, n0, n1, n2, C0, C1, C2, C3)

        # generate keystream matrix
        k1 = generate_key_stream(m_1)[0]

        # concatenate all elements of matrix
        keystream = keystream + ''.join(list(map(my_join, k1))).replace("0b", "")
        local_counter = counter_update(local_counter)

    return '0b' + keystream


# FALTA FAZER UMA ATUALIZAÇÃO DE CHAVE
def update_key(current_key, counter, key=None, nonce=None, c0=None, c1=None, c2=None, c3=None):
    """
    :param current_key: a chave atual que esta com menos de 1024 bits
    :param key: a chave para gerar a matriz chacha
    :param counter: contador atualizado
    :param nonce: nonce escolhido padrao
    :param c0: constante 0
    :param c1:  constante 1
    :param c2:  constante 2
    :param c3:  constante 3
    :return: retorna a chave atualizada e o contador atualizado
    """
    if key is None:
        key1 = KEY
    else:
        key1 =key
    if nonce is None:
        N0, N1, N2 = NONCE0, NONCE1, NONCE2
    else:
        N0, N1, N2 = nonce[0], nonce[1], nonce[1]

    count = counter_update(counter)
    mm = generate_chacha_matrix(key1, count, N0, N1, N2, C0, C1, C2, C3)
    kk = generate_key_stream(mm)[0]
    kk = ''.join(list(map(my_join, kk))).replace("0b", "")

    return current_key + kk, count


# Funcionando aparentemente
def event_cd(u0, u1, k, ep=None, en=None, cd=True):
    """
    Entrega os eventos no processo de encriptação decriptação
    :param ep: evento proibido
    :param u0:-> leitura anterior
    :param u1:-> leitura atual
    :param k: -> chave atual
    :param e_n: -> evento nulo
    :param cd: -> escolhe o modo de cifragem ou decifragem: default -> True cifra
    :return: tupla (evento em binário e evento em forma de lista)
    """
    if en is None:
        en = [0] * len(u0)
    if ep is None:
        ep = [1] * len(u0)

    # transformando para binário os parametros da função
    u_0 = '0b' + ''.join(map(str, u0))
    u_1 = '0b' + ''.join(map(str, u1))
    e_p = '0b' + ''.join(map(str, ep))
    e_n = '0b' + ''.join(map(str, en))

    if not cd:
        aux = e_p
        e_p = e_n
        e_n = aux

    if u_0 == u_1:
        return [0] * len(u0), '0b' + ''.join(map(str, [0] * len(u0)))

    # definindo evento de entrada
    e_0 = xor(u_0, u_1)  # vemos a mudança na leitura dos sensores
    # print('evento 0', e_0)
    e_1 = xor(e_0, k)  # evento de saída
    # print('evento saida', e_1)
    # print('evento nulo', e_n)

    if e_n == '0b' + e_1[-len(u0):]:
        return list(map(int, xor(e_p, k)[-len(u0):])), '0b' + xor(e_p, k)[-len(u0):]
    else:
        return list(map(int, e_1[-len(u0):])), '0b' + e_1[-len(u0):]


# Funcionando aparentemente
def get_cipher(u0, u1, c0, k, ep=None, en=None):
    c_0 = '0b' + ''.join(map(str, c0))

    if en is None:
        en = [0] * len(u0)
    if ep is None:
        ep = [1] * len(u0)

    e_cif = event_cd(u0, u1, k, ep, en)[1]  # alterar nome para evento de saída
    # print('e_cif', e_cif)
    return [list(map(int, xor(e_cif, c_0)[-len(u0):])), '0b' + xor(e_cif, c_0)[-len(u0):]]


# Funcionando aparentemente
def get_plain(c0, c1, u0, k, ep=None, en=None):
    u_0 = '0b' + ''.join(map(str, u0))

    if en is None:
        en = [0] * len(c0)
    if ep is None:
        ep = [1] * len(c0)

    e_cif = event_cd(c0, c1, k, ep, en, False)[1]
    # print('e_cif', e_cif)
    return [list(map(int, xor(e_cif, u_0)[-len(c0):])), '0b' + xor(e_cif, u_0)[-len(c0):]]


if __name__ == "__main__":
    g_counter = '0b' + '0' * 30 + '11'
    ks = generate_initial_keystream()

    # U0 = [1, 0, 1, 1, 1]
    # U1 = [1, 1, 0, 0, 1]

    # U_list = [[1, 1, 1, 1, 0], [1, 0, 0, 1, 1], [0, 0, 1, 1, 0], [1, 1, 0, 0, 0], [1, 1, 0, 0, 0], [1, 0, 0, 0, 0]]
    generate_random_plain(8, 200)
    U_list = read_vect('vec')
    u0 = U_list[0]
    c0 = u0
    C_list = []
    C_list.append(c0)
    # arquivo para guardar as chaves
    k_plain = open('keyplain.txt', 'w')
    # for nos elementos remanscentes da lista
    for u1 in U_list[1:]:
        current_key = ks[:2 + len(u1)]
        k_plain.write(current_key+'\n')
        # print(current_key)
        # print(u0, u1, c0, current_key)
        cipher = get_cipher(u0, u1, c0, current_key)
        C_list.append(cipher[0])

        # verificando se o evento não será nulo
        if u1 != u0:
            ks = '0b' + ks[2 + len(u1):]

        # atualização dos parametros
        u0 = u1
        c0 = cipher[0]

        if len(ks) < 1024:
            print('passou')
            print(len(ks), g_counter)
            ks, g_counter = update_key(ks, g_counter)
            print(len(ks), g_counter)

    k_plain.close()

    print('Plain', U_list)
    print('Cipher', C_list)

    # gera novo counter e nova keystream completa
    g_counter = '0b' + '0' * 30 + '11'
    ks = generate_initial_keystream()

    # CRIANDO UM ARQUIVO COM O CIPHERTEXT
    record_vec_in_file(C_list,'cipher')
    C_list = read_vect('cipher')

    c0 = C_list[0]
    u0 = c0
    R_list = []
    R_list.append(c0)
    # Gravando as chaves utilizadas no ciphertext
    k_cipher = open('k_cipher.txt', 'w')
    for c1 in C_list[1:]:
        current_key = ks[:2 + len(u1)]
        k_cipher.write(current_key+'\n')
        # print(current_key)
        # print(u0, u1, c0, current_key)
        plain_text = get_plain(c0, c1, u0, current_key)
        R_list.append(plain_text[0])

        # verificando se o evento não será nulo
        if c1 != c0:
            ks = '0b' + ks[2 + len(u1):]

        # atualização dos parametros
        c0 = c1
        u0 = plain_text[0]

        if len(ks) < 1024:
            print(len(ks), g_counter)
            print('passou')
            ks, g_counter = update_key(ks, g_counter)
            print(len(ks), g_counter)

    k_cipher.close()
    print('Plain ', R_list)

    # GUARDANDO O RETORNO DO PLAINTEXT
    record_vec_in_file(R_list, 'back_to_plain')
    print(ks)
# TOMAR CUIDADO PARA ZERAR O CONTADOR E TRABALHAR COM UMA LISTA TXT PARA A ENTRADA DE DADOS
# FALTA FAZER O UPDATE DA KEYSTREAM E TESTAR COM len(ks)<32, 40, 50 bits por exemplo

# INPLEMENTAR RECEBENDO UM TXT
# GERAR UMA LISTA NO PYTHON - TRANSFORMAR PARA TXT
