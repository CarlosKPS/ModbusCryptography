# -*- coding: utf-8 -*-
"""
Created on Fri Jan 28 17:38:13 2022
Classe de cifrar a mensagem utilizando chacha
@author: carlos
"""

from Chacha.mchacha.chacha_operations import *
from Chacha.mchacha.constants import *

import timeit

class Chacha20Cifra():
    
    def __init__(self, databank, n_bits=64, key=None, nonce=None, const=None):
        
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
        self._databank = databank
        self._nbist = n_bits
        
        # Chave de fluxo inicial
        
        self._keystream = self.create_key()
        
        # as cifras utilizadas
        self._ca = []
        self._cf = []
        self._cifra_lista =[]
        self._n = 1
    
    def create_key(self):
        """
        Returns
        -------
        A matrix de keystream Chacha20

        """
        chacha_original = generate_chacha_matrix(self._key, self._counter, self._nonce[0], 
                                                 self._nonce[1], self._nonce[2], 
                                                 self._mconstants[0], self._mconstants[1],
                                                 self._mconstants[2], self._mconstants[3])
        for i in range(0,10):
            chacha_original = chacha_round(chacha_original)
        
        self.counter_update()
        self._keystream = chacha_original
        self._keystream = ''.join([key for l in chacha_original for key in l]).replace("0b", "")
        self._keystream = [int(d) for d in self._keystream]
        
        return self._keystream

    
    def counter_update(self):
        add = bin(int(self._counter, 2) + 1)
        diff = abs(len(add) - 34)
        self._counter = '0b' + '0' * diff + add[2:]
        return self._counter
        
        
    def cifrar_mensagem(self, pa, pf, mca):
        e = []
        ec = []
        if pa != pf:
            key = self._keystream[:len(pf)]
            e = [i^j for i,j in zip(pa,pf)]
            ec = [i^j for i,j in zip(e,key)]
            mcf = [i^j for i,j in zip(mca, ec)]
            print("cifrou a mensagem \n")
            self._keystream = self._keystream[len(pf):]
            self._cifra_lista.append(mcf)
            return mcf
        else:
            print("não cifrou a mensagem \n")
            return self._cifra_lista
        
        
        