# -*- coding: utf-8 -*-
"""
Created on Fri Jan 28 00:25:21 2022
Cliente modbus
@author: carlo
"""

from pyModbusTCP.client import ModbusClient
from time import sleep
from Chacha_class_cripto import Chacha20Cifra
from time import time

from RSA.Constants import *
from RSA.ClassRSA import *

class SimpleModbusClient():
    
    def __init__(self, host='localhost',port=502, scan_time = 1):
        
        self._cliente = ModbusClient(host=host, port=port)
        self._scan_time = scan_time
        self._host = host
        self._port = port
        self._timelist = []
        
    def run(self, show_iter = True):
        self._cliente.open()
        
        try:
            # Starting a loop
            while True:
                start_time = time()
                coil_val = self._cliente.read_coils(0,2000-9)
                end_time = time()
                if show_iter:
                    print("Observed coils: \n", coil_val)
                    print("tempo de leitura", end_time-start_time)
                    self._timelist.append(end_time-start_time)
                sleep(self._scan_time)
        except Exception as e:
            print("Error", e.args)


class SimpleModbusRSAClient():
    
    def __init__(self, host='localhost',port=502, scan_time = 0.5):
        
        self._cliente = ModbusClient(host=host, port=port)
        self._scan_time = scan_time
        self._host = host
        self._port = port
        self._timelist = []
        
    def run(self, show_iter = True):
        self._cliente.open()
        
        try:
            # Starting a loop
            while True:
                start_time = time()
                coil_val = self._cliente.read_coils(0,2000-9)
                end_time = time()
                if show_iter:
                    print("Observed coils: \n", coil_val)
                    print("tempo de leitura", end_time-start_time)
                    self._timelist.append(end_time-start_time)
                sleep(self._scan_time)
        except Exception as e:
            print("Error", e.args)


class ClienteModbusChacha20():
    
    def __init__(self, host, port, scan_time=1):
        
        self._cliente = ModbusClient(host=host, port=port)
        self._scan_time = scan_time
        self._criptofunc = Chacha20Cifra(None, 64)
    
    def atendimento(self):
        """
        Atendimento ao usu??rio

        """
        # abrindo o cliente
        self._cliente.open()
        
        # criando um vetor auxiliar  ----- OLD  
        aux_coil = self._cliente.read_coils(0,64)
        
        # primeira lista que servir?? como base 
        self._criptofunc._cifra_lista.append(aux_coil)
        
        try:
            # Iniciando o loop
            while True:
                # Armazenando os valores dos 64bits de coil numa variavel
                coil_val = self._cliente.read_coils(0,64)
                print("bobinas observadas: \n", coil_val)
                
                # func????o para cifrar a mensagem
                self._criptofunc.cifrar_mensagem(aux_coil, 
                                                 coil_val, 
                                                 self._criptofunc._cifra_lista[-1])
                
                aux_coil = coil_val
                sleep(self._scan_time)
        
        except Exception as e:
            print("Error". e.args)
            
            


        