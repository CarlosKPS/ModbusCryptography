# -*- coding: utf-8 -*-
"""
Servidor de uma rede modbus
"""

from pyModbusTCP.server import ModbusServer, DataBank
from time import sleep
from RSA.Constants import *
from RSA.ClassRSA import *
import random
from time import time
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
                      self._tabmodbus.get_bits(0,64))
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
                start_time = time()
                self._tabmodbus.set_bits(1, self._crip.encryptRSA(self._current_plain))
                end_time = time()
                self._timelist.append(end_time - start_time)
                print("conjunto de bits monitoradoes: ", 
                      self._tabmodbus.get_bits(0,2000-9))
                sleep(2)
        except:
            print("servidor desligado")
    
    def update_data(self):
        self._current_plain = self._plainlist[self._i%5]
        self._i += 1


def generate_random_vec(lenght=64):
    vec_list = []
    for i in range(0,lenght):
        vec_list.append(random.randrange(0,2,1))
    return vec_list