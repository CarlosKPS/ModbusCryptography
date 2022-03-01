from Chacha.mchacha.chacha_operations import *
from Chacha.mchacha.constants import *
from time import time


class ChachaEncrypt:
    def __init__(self, key=None, nonce=None, const=None):

        # constants and relevant things for matrix formation
        if nonce is None:
            nonce = [NONCE0, NONCE1, NONCE2]
        if const is None:
            const = [C0, C1, C2, C3]  # Top matrix constants (magic numbers)
        # values from constructor
        if key is None:
            key = KEY

        self.m_constant = const  # magic numbers
        self.key = key  # The algorithm key
        self.nonce = nonce  # o nonce

        # create a counter and a key order
        self.counter = COUNTER  # the counter
        self.key_order = [0, 0]  # the ith,jth element of encrypted matrix
        self.current_key = ''  # return the present key in each encrypt

        # The pre round matrix
        self.chacha_M = generate_chacha_matrix(self.key, self.counter, self.nonce[0],
                                               self.nonce[1], self.nonce[2], self.m_constant[0],
                                               self.m_constant[1], self.m_constant[2], self.m_constant[3])
        self.encrypted_chacha_M = []

        # To storage cipher texts
        self.present_cipher = ''
        self.historical_cipher = []

        self.n_matrix = 0

    def encrypt(self, plain_text):
        """
        :param: plain_text: a binary entry in str format '0b001' or '010100101'
        :return: ciphertext in binary base
        """

        if plain_text[:2] == '0b':
            diff = abs(34 - len(plain_text))  # diff variable to add zeros if necessary
            p_text = '0b' + '0' * diff + plain_text[2:]  # to mount plaintext in binary
        else:  # if the input is in the form 0111010101101
            diff = abs(32 - len(str(plain_text)))  # the difference between the input and 32 bits
            p_text = '0b' + '0' * diff + str(plain_text)  # mount a plaintext in binary

        # In this line the encryption occurs.
        # Do a xor operation between plaintext and a given key inside the encrypted chacha matrix
        self.present_cipher = xor(p_text, self.encrypted_chacha_M[self.key_order[0]][self.key_order[1]])
        self.historical_cipher.append(self.present_cipher)

        # Update next key_order
        self.update_key()

        return self.present_cipher

    def generate_encrypted_matrix(self):
        """
        This functions also update the counter
        :return: Current encrypted matrix
        """
        # first chacha round
        # create a new basis chacha matrix
        self.encrypted_chacha_M = chacha_round(self.get_chacha_matrix())

        # range for remaining rounds
        for i in range(0, 9):
            self.encrypted_chacha_M = chacha_round(self.encrypted_chacha_M)

        # update the counter
        self.counter_update()

        # return encrypted matrix
        return self.encrypted_chacha_M

    def update_key(self):
        """
        This function update the key will be utilized in each encryption.
        :return: The indices of next number that will 'xorized' with the plaintext
        """
        # take the next element of the line
        self.key_order[1] += 1

        # If the jth term is m than 3 its mean that all elements of a row was totally traveled
        if self.key_order[1] > 3:
            self.key_order[0] += 1  # this mean next line
            self.key_order[1] = 0  # first column
            # If the the all lines
            if self.key_order[1] > 3:
                self.key_order = [0, 0]
        # update the current key
        self.current_key = self.encrypted_chacha_M[self.key_order[0]][self.key_order[1]]

        return self.key_order

    def counter_update(self):
        add = bin(int(self.counter, 2) + 1)
        diff = abs(len(add) - 34)
        self.counter = '0b' + '0' * diff + add[2:]
        return self.counter

    def get_encrypted_matrix(self):
        return self.encrypted_chacha_M

    def get_chacha_matrix(self):
        """
        :return: The Matrix ready to chacha round (ready to generate a encrypted matrix from it) if the counter was
        updated it will be consider in this matrix
        """
        self.chacha_M = generate_chacha_matrix(self.key, self.counter, self.nonce[0],
                                               self.nonce[1], self.nonce[2], self.m_constant[0],
                                               self.m_constant[1], self.m_constant[2], self.m_constant[3])
        return self.chacha_M

    def get_status(self):
        print("Número da matrix encriptada gerada: ", self.n_matrix)
        print("Current key: ", self.encrypted_chacha_M[self.key_order[0]][self.key_order[1]])
        print("Encriptações feitas: ")


class Chacha20Cifra():

    def __init__(self, n_bits=64, key=None, nonce=None, const=None):

        if nonce is None:
            nonce = [NONCE0, NONCE1, NONCE2]
        if const is None:
            const = [C0, C1, C2, C3]  # Top matrix constants (magic numbers)
        # values from constructor
        if key is None:
            key = KEY

        # setando as constantes da matriz do chacha
        self._mconstants = const
        self._key = key
        self._nonce = nonce
        self._counter = COUNTER

        # setando aquilo que será cifrado
        # self._databank = databank
        self._nbist = n_bits

        # Chave de fluxo inicial

        self._keystream = self.create_key()

        # as cifras utilizadas
        self._ca = []
        self._cf = []
        self._cifra_lista = []
        self._n = 1

    def create_key(self):
        """
        Returns
        -------
        A matrix de keystream Chacha20

        """
        start_time = time()
        chacha_original = generate_chacha_matrix(self._key, self._counter, self._nonce[0],
                                                 self._nonce[1], self._nonce[2],
                                                 self._mconstants[0], self._mconstants[1],
                                                 self._mconstants[2], self._mconstants[3])
        chacha_aux = chacha_original
        for i in range(0, 10):
            chacha_original = chacha_round(chacha_original)

        self.counter_update()
        # self._keystream = chacha_original
        self._keystream = [[chacha_aux[i][j] + chacha_original[i][j] for j in range(0, len(chacha_aux[0]))] for i in
                           range(0, len(chacha_aux))]
        self._keystream = ''.join([key for l in chacha_original for key in l]).replace("0b", "")
        self._keystream = [int(d) for d in self._keystream]
        print("O tempo para gerar uma matriz é: ", start_time - time())
        return self._keystream

    def counter_update(self):
        add = bin(int(self._counter, 2) + 1)
        diff = abs(len(add) - 34)
        self._counter = '0b' + '0' * diff + add[2:]
        return self._counter

    def encrypt(self, pa, pf, c0, e_n=None, e_p=None):
        """
        pa: estado anterior
        pf: estado atual
        c0: cifra anterior
        e_n: evento nulo
        e_p: evento proibido
        """
        key = self._keystream[:len(pa)]
        e_out = event_cd(pa, pf, key, en=e_n, ep=e_p)
        self._keystream = self._keystream[len(pf):]
        return [i ^ j for i, j in zip(e_out, c0)]

    def decrypt(self, pa, pf, c0, e_n=None, e_p=None):
        """
        pa: estado cifrado anterior
        pf: estado cifrado atual
        C0: texto claro anterior
        e_n: evento nulo
        e_p: eventro proibido
        """
        key = self._keystream[:len(pa)]
        e_out = event_cd(pa, pf, key, en=e_n, ep=e_p, cd=False)
        self._keystream = self._keystream[len(pf):]
        return [i ^ j for i, j in zip(e_out, c0)]
