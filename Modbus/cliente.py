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

    def __init__(self, host='localhost', port=502, scan_time=0.5, mensage_lenght=64):

        self._cliente = ModbusClient(host=host, port=port)
        self._scan_time = scan_time
        self._host = host
        self._port = port
        self._mensage_leght = mensage_lenght
        self._decrip = CifraRSA()
        self._timelist = []
        self._decrption_list = []

    def run(self, show_iter=True):
        self._cliente.open()

        try:
            # Starting a loop
            while True:
                start_time = time()
                # coil_val = [1 if i==True else 0  for i in self._cliente.read_coils(0,2000)]
                # print(len(coil_val))
                aux_vec = self._decrip.decriptRSA([1 if i == True else 0 for i in self._cliente.read_coils(0, 2000)])
                print(len(aux_vec))
                self._decrption_list.append([0] * (self._mensage_leght - len(aux_vec)) + aux_vec)
                print(len(self._decrption_list[-1]))
                end_time = time()
                if show_iter:
                    # print("Observed coils: \n", coil_val)
                    print("tempo de leitura", end_time - start_time)
                    self._timelist.append(end_time - start_time)
                sleep(self._scan_time)
        except Exception as e:
            print("Error", e.args)


class ClienteModbusChacha20():

    def __init__(self, host='localhost', port=502, scan_time=1):

        self._cliente = ModbusClient(host=host, port=port)
        self._scan_time = scan_time
        # ----------------------------------------------------------
        # Atributos para o processo de decifrar uma mensagem
        self._chacha20 = Chacha20Cifra()
        self._ca = VEC_PLAINTEX[0]  # Cifra atual
        self._cf = []  # Cifra final
        self._back_to_plain = [VEC_PLAINTEX[0]]  # Devolta ao texto claro

        # Medição de tempo
        self._time_list = []

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
                start_time = time_ns()
                # self._cf = self._cliente.read_coils(0, 16)  # Armazena na cifra atual
                # Realiza a decriptação e realiza um append no vetor back to plain
                print("----------------------------------------------------------------------------------------------")
                print("ca: ", self._ca)
                print("cf: ", self._cf)

                if self._cliente.read_coils(0, 16) is None:
                    self._cf = self._ca
                    print("cf: ", self._cf)
                    print("Não inicou")
                else:
                    self._cf = [1 if i == True else 0 for i in self._cliente.read_coils(0, 16)]
                    print("cf: ", self._cf)
                    print("Servidor on")

                self._back_to_plain.append(
                    self._chacha20.decrypt(self._ca, self._cf, self._back_to_plain[-1])
                )
                self._ca = self._cf
                end_time = time_ns()

                self._time_list.append((end_time - start_time) / 1e9)
                sleep(self._scan_time)

        except Exception as e:
            print("Error".e.args)
