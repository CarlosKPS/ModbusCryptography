# -*- coding: utf-8 -*-
"""
Servidor de uma rede modbus
"""

from pyModbusTCP.server import ModbusServer, DataBank
from time import sleep
from RSA.Constants import *
from RSA.ClassRSA import *
from Chacha.classes.chacha import *
import random
from time import time, time_ns
import datetime as dt


class ServidorModbus():

    def __init__(self, host_ip, port):

        self._servidor = ModbusServer(host=host_ip, port=port, no_block=True)
        self._tabmodbus = DataBank()

    def run(self):
        """
        Execução da tabela Modbus

        """

        try:
            self._servidor.start()
            print("Em execução")
            while True:
                print("conjunto de bits monitoradoes: ",
                      self._tabmodbus.get_bits(0, 64))
                sleep(2)
        except:
            print("servidor desligado")

    def update_data(self):
        pass


class ServidorModbusRSA():

    def __init__(self, host_ip='localhost', port=502):

        self._servidor = ModbusServer(host=host_ip, port=port, no_block=True)
        self._tabmodbus = DataBank()
        self._tabmodbus.set_bits(0, [1])
        self._crip = CifraRSA()
        # self._plainlist = PLAIN_VEC
        self._plainlist = read_vector_from_list()  # Lê todos os vetores de 10 Bits
        self._current_plain = []
        self._i = 0
        # Para armazenar informações
        self._timelist = []
        self._cipher = []

    def run(self):
        """
        Execução da tabela Modbus

        """
        try:
            self._servidor.start()
            print("Em execução")
            while True:
                # Atualizar o tabela modbus que será utilizada
                self.update_data()
                #print("Texto claro atual: ", self._current_plain)
                # conta o tempo para cifrar a mensagem e guardar na tabela modbus
                start_time = time_ns()
                # Fazer com que tenha 2000 bits
                aux1 = self._crip.encryptRSA(self._current_plain)  # verificar a quantidade de bits que há.
                n_zeros = [0] * (2000 - len(aux1))
                self._tabmodbus.set_bits(0, n_zeros + aux1)
                end_time = time_ns()
                print("Tempo para cifrar: ", (end_time - start_time)/1e9)
                # guarda os valores de tempo numa lista
                #print("Tamanho da mensagem:", len(n_zeros + aux1))
                self._timelist.append((end_time - start_time)/1e9)
                #print("conjunto de bits monitoradoes: ",
                #  self._tabmodbus.get_bits(0, 2000))
                self._cipher.append(n_zeros + aux1)  # Cria a lista do texto cifrado
                print(self._i)
                sleep(2)
        except:
            create_txt_from_vector(self._cipher, 'RSA-Modbus-Ciphertext.txt')
            create_txt_from_vector(self._timelist, 'RSA-Modbus-TimeToEncrypt.txt')
            print("A média para cifrar um evento é de: ", mean_from_time_vector(self._timelist))

            print("servidor desligado")

    def update_data(self):
        self._current_plain = self._plainlist[self._i % len(self._plainlist)]
        self._i += 1


class ServidorModbusChacha20():

    def __init__(self, host_ip='localhost', port=502):
        # -------------------------------------------------------------------------------------------------------------
        # carregando os vetores de teste
        test_vect = read_vector_from_list()
        # ------------------------------------------------------------------------------------------------------------
        self._servidor = ModbusServer(host=host_ip, port=port, no_block=True)  # Servidor
        self._tabmodbus = DataBank()  # Tabela Modbus
        # self._tabmodbus.set_bits(0, VEC_PLAINTEX[0])
        self._tabmodbus.set_bits(0, test_vect[0])
        # ------------------------------------------------------------------------------------------------------------
        self._chacha20 = Chacha20Cifra()  # Class da cifra Chacha20
        # ------------------------------------------------------------------------------------------------------------
        # Texto claro
        # self._plaintext = VEC_PLAINTEX  # texto claro que será feito o upload
        self._plaintext = test_vect # texto claro que será feito o upload

        self._i = 0  # contador auxiliar para rodar os textos
        # -----------------------------------------------------------------------------------------------------------
        # self._pa = VEC_PLAINTEX[0]  # Texto claro atual
        self._pa = test_vect[0]  # Texto claro atual
        # self._cipher = [VEC_PLAINTEX[0]]  # Texto cifrado atual
        self._cipher = [test_vect[0]]  # Texto cifrado atual
        self._pf = []

        # Lista para descobrir o tempo
        self._time_list = []

    def run(self):
        """
        Execução da tabela Modbus

        """

        try:
            self._servidor.start()
            sleep(10)
            print("Em execução")
            while True:
                # Pega os estados
                self.update_data()
                # print("Estados que irão gerar os eventos: ", coil_val)
                # print("Tamanho da mensagem: ", len(coil_val))
                # -----------------------------
                # Para verificar Pa e Pf
                # print("pa: {0}.    Bits: {1}".format(self._pa, len(self._pa)))
                # print("pf: {0}.    Bits: {1}".format(self._pf, len(self._pf)))
                # -----------------------------

                # Cifra a mensagem e coloca na tabela Modbus
                start_time = time_ns()
                self._tabmodbus.set_bits(0, self._chacha20.encrypt(self._pa, self._pf, self._cipher[-1]))
                # -----------------------------
                # adiciona o ultimo resultado na lista cipher
                self._cipher.append(self._tabmodbus.get_bits(0, 10))
                # Toma o ultimo texto claro
                self._pa = self._pf
                end_time = time_ns()
                #print("Ciphertext: {0}    Bits: {1}".format(self._cipher[-1], len(self._cipher[-1])))
                self._time_list.append((end_time - start_time)/1e9)  # salvando o tempo de execução
                # self._tabmodbus.set_bits(0, self._cipher[-1])
                # self._tabmodbus.set_bits(0, self._cipher[-1]) # Salva os bist na tabela Modbus
                # self._pa.append(coil_val) # atualiza os valores de Pa
                print(self._i)
                sleep(2.3)
        except:
            print("servidor desligado")
            create_txt_from_vector(self._cipher, 'ChaCha20-Modbus-Chipertext.txt')
            create_txt_from_vector(self._time_list, 'ChaCha20-Modbus-TimeToEncrypt.txt')
            print("A média para cifrar um evento é de: ", mean_from_time_vector(self._time_list))

    def update_data(self):
        self._pf = self._plaintext[self._i % 20]
        self._i += 1


def generate_random_vec(lenght=64):
    vec_list = []
    for i in range(0, lenght):
        vec_list.append(random.randrange(0, 2, 1))
    return vec_list


def read_vector_from_list(n_list=100):
    aux_list = []
    vec_list = []
    with open(r"plaintext.txt", 'r') as f:
        lines = f.readlines()[:n_list]
    for l in lines:
        aux_list.append(l.strip("\n").strip("]").strip("[").replace(" ", "").replace(",", ""))
    for element in aux_list:
        vec_list.append([int(i) for i in element])
    f.close()
    return vec_list


def create_txt_from_vector(vec, file_name):
    f = open(file_name, "w+")
    for i in vec:
        f.write("{0}\n".format(i))
    f.close()
    return 0


def mean_from_time_vector(time_vec):
    """
    Função para tirar a média de um vetor tirando todos os resultados iguais a zeros
    time_vec: vetor com os tempos armazenados
    return: uma tupla com os valores da média e o numero da amostra excluindo-se os zeros
    """
    aux_time_vec = [i for i in time_vec if i != 0]
    return sum(aux_time_vec) / len(aux_time_vec), len(aux_time_vec)
