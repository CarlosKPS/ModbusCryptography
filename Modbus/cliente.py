# -*- coding: utf-8 -*-
"""
Created on Fri Jan 28 00:25:21 2022
Cliente modbus
@author: carlo
"""

from pyModbusTCP.client import ModbusClient
from time import sleep
from Chacha.classes.chacha import *
from time import time, time_ns

from RSA.Constants import *
from RSA.ClassRSA import *


class SimpleModbusClient():

    def __init__(self, host='localhost', port=502, scan_time=1):

        self._cliente = ModbusClient(host=host, port=port)
        self._scan_time = scan_time
        self._host = host
        self._port = port
        self._timelist = []

    def run(self, show_iter=True):
        self._cliente.open()

        try:
            # Starting a loop
            while True:
                start_time = time()
                coil_val = self._cliente.read_coils(0, 2000 - 9)
                end_time = time()
                if show_iter:
                    print("Observed coils: \n", coil_val)
                    print("tempo de leitura", end_time - start_time)
                    self._timelist.append(end_time - start_time)
                sleep(self._scan_time)
        except Exception as e:
            print("Error", e.args)


class SimpleModbusRSAClient():

    def __init__(self, host='localhost', port=502, scan_time=0.5, mensage_lenght=10):

        self._cliente = ModbusClient(host=host, port=port)
        self._scan_time = scan_time
        self._host = host
        self._port = port
        self._mensage_leght = mensage_lenght
        self._decrip = CifraRSA()
        self._timelist = []
        self._timelist_read_coil = []
        self._decrption_list = []

    def run(self, show_iter=True):
        self._cliente.open()

        try:
            # Starting a loop
            while True:
                start_time = time_ns()
                coil_val = [1 if i == True else 0 for i in self._cliente.read_coils(0, 2000)]
                end_time = time_ns()
                print("Tempo para ler a mensagem: ", (end_time - start_time) / 1e9)
                self._timelist_read_coil.append((end_time - start_time) / 1e9)  # Tempo de leitura dos 2000 bits
                # print(len(coil_val))
                # aux_vec = self._decrip.decriptRSA([1 if i == True else 0 for i in self._cliente.read_coils(0, 2000)])
                start_time = time_ns()
                aux_vec = self._decrip.decriptRSA(coil_val)
                # print(len(aux_vec))
                self._decrption_list.append([0] * (self._mensage_leght - len(aux_vec)) + aux_vec)
                # print(len(self._decrption_list[-1]))
                end_time = time_ns()
                print("Tempo para decriptar: ", (end_time - start_time) / 1e9)
                if show_iter:
                    # print("Observed coils: \n", coil_val)
                    # print("tempo de leitura", end_time - start_time)
                    self._timelist.append((end_time - start_time) / 1e9)
                sleep(self._scan_time)
        except:
            create_txt_from_vector(self._decrption_list, 'RSA-Modbus-BackToPlaintext.txt')
            create_txt_from_vector(self._timelist, 'RSA-Modbus-TimeToDecrypt.txt')
            create_txt_from_vector(self._timelist_read_coil, 'RSA-Modbus-TimeToReadCiphertext.txt')

            print("Tempo médio de leitura das bobinas: ", mean_from_time_vector(self._timelist_read_coil))
            print("Tempo médio para decriptar uma mensagem:", mean_from_time_vector(self._timelist))

            print("Cliente desligado")


class ClienteModbusChacha20():

    def __init__(self, host='localhost', port=502, scan_time=1):

        test_vect = read_vector_from_list()

        self._cliente = ModbusClient(host=host, port=port)
        self._scan_time = scan_time
        # ----------------------------------------------------------
        # Atributos para o processo de decifrar uma mensagem
        self._chacha20 = Chacha20Cifra()
        # self._ca = VEC_PLAINTEX[0]  # Cifra atual
        self._ca = test_vect[0]  # Cifra atual
        self._cf = []  # Cifra final
        # self._back_to_plain = [VEC_PLAINTEX[0]]  # Devolta ao texto claro
        self._back_to_plain = [test_vect[0]]  # Devolta ao texto claro
        # Medição de tempo
        self._time_list = []
        self._timelist_read_coil = []

    def run(self):
        """
        Atendimento ao usuário

        """
        # abrindo o cliente
        self._cliente.open()

        try:
            # Iniciando o loop
            while True:

                # funcção para cifrar a mensagem
                # start_time = time_ns()
                # self._cf = self._cliente.read_coils(0, 16)  # Armazena na cifra atual
                # Realiza a decriptação e realiza um append no vetor back to plain
                # print("----------------------------------------------------------------------------------------------")
                # print("ca: ", self._ca)
                # print("cf: ", self._cf)

                if self._cliente.read_coils(0, 10) is None:
                    self._cf = self._ca
                    # print("cf: ", self._cf)
                    # print("Não inicou")
                else:
                    start_time = time_ns()
                    self._cf = [1 if i == True else 0 for i in self._cliente.read_coils(0, 10)]
                    end_time = time_ns()
                    self._timelist_read_coil.append((end_time - start_time) / 1e9)
                    # print("cf: ", self._cf)
                    # print("Servidor on")

                start_time = time_ns()
                self._back_to_plain.append(
                    self._chacha20.decrypt(self._ca, self._cf, self._back_to_plain[-1])
                )
                self._ca = self._cf
                end_time = time_ns()

                self._time_list.append((end_time - start_time) / 1e9)
                sleep(self._scan_time)

        except:
            create_txt_from_vector(self._back_to_plain, 'ChaCha20-Modbus-BackToPlaintext.txt')
            create_txt_from_vector(self._time_list, 'ChaCha20-Modbus-TimeToDecrypt.txt')
            create_txt_from_vector(self._timelist_read_coil, 'ChaCha20-Modbus-TimeToReadCiphertext.txt')

            print("Tempo médio de leitura das bobinas: ", mean_from_time_vector(self._timelist_read_coil))
            print("Tempo médio para decriptar uma mensagem:", mean_from_time_vector(self._time_list))

            print("Cliente encerrado")


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
