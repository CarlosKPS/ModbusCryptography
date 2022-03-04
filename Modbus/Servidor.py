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
        self._plainlist = PLAIN_VEC
        self._current_plain = []
        self._i = 0
        self._timelist = []

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

                # conta o tempo para cifrar a mensagem e guardar na tabela modbus
                start_time = time()
                # Fazer com que tenha 2000 bits
                aux1 = self._crip.encryptRSA(self._current_plain)  # verificar a quantidade de bits que há.
                n_zeros = [0] * (2000 - len(aux1))
                self._tabmodbus.set_bits(0, n_zeros + aux1)
                end_time = time()
                # guarda os valores de tempo numa lista
                print("Tamanho da mensagem:", len(n_zeros + aux1))
                self._timelist.append(end_time - start_time)
                print("conjunto de bits monitoradoes: ",
                      self._tabmodbus.get_bits(0, 2000))
                sleep(2)
        except:
            print("servidor desligado")

    def update_data(self):
        self._current_plain = self._plainlist[self._i % 5]
        self._i += 1


class ServidorModbusChacha20():

    def __init__(self, host_ip='localhost', port=502):
        # ------------------------------------------------------------------------------------------------------------
        self._servidor = ModbusServer(host=host_ip, port=port, no_block=True)  # Servidor
        self._tabmodbus = DataBank()  # Tabela Modbus
        self._tabmodbus.set_bits(0, VEC_PLAINTEX[0])
        # ------------------------------------------------------------------------------------------------------------
        self._chacha20 = Chacha20Cifra()  # Class da cifra Chacha20
        # ------------------------------------------------------------------------------------------------------------
        self._pa = VEC_PLAINTEX[0]  # Texto claro atual
        self._cipher = [VEC_PLAINTEX[0]]  # Texto cifrado atual
        self._pf = []

        # Texto claro
        self._plaintext = VEC_PLAINTEX  # texto claro que será feito o upload
        self._i = 0  # contador auxiliar para rodar os textos

        # Lista para descobrir o tempo
        self._time_list = []

    def run(self):
        """
        Execução da tabela Modbus

        """

        try:
            self._servidor.start()
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
                end_time = time_ns()
                # -----------------------------
                # adiciona o ultimo resultado na lista cipher
                self._cipher.append(self._tabmodbus.get_bits(0, 16))
                # Toma o ultimo texto claro
                self._pa = self._pf
                print("Ciphertext: {0}    Bits: {1}".format(self._cipher[-1], len(self._cipher[-1])))
                self._time_list.append((end_time - start_time))  # salvando o tempo de execução
                # self._tabmodbus.set_bits(0, self._cipher[-1])
                # self._tabmodbus.set_bits(0, self._cipher[-1]) # Salva os bist na tabela Modbus
                # self._pa.append(coil_val) # atualiza os valores de Pa
                sleep(1)
        except:
            print("servidor desligado")

    def update_data(self):
        self._pf = self._plaintext[self._i % 20]
        self._i += 1


def generate_random_vec(lenght=64):
    vec_list = []
    for i in range(0, lenght):
        vec_list.append(random.randrange(0, 2, 1))
    return vec_list
