# -*- coding: utf-8 -*-
"""
Created on Tue Feb  1 21:13:46 2022

@author: carlo
"""
from RSA.Constants import *
from RSA.Functions import *
from timeit import timeit

class CifraRSA():
    
    def __init__(self, p=PRIME1, q=PRIME2,e=None, d=None):
        
        self._p = p
        self._q = q
        self._n = p*q
        self._phin = (p-1)*(q-1)
        
        if not(e):
            self._e = EXAMPLE_E
        else:
            self._e = self.set_e()
        if not(d):
            self._d = EXAMPLE_D
        else:
            self._d = self.set_d()
        print(bgcd(self._e, self._phin))
    
    def encryptRSA(self, m, lista = True):
        mensagem = ''
        if type(m) == list:
            # primeiramente gera-se um numero binario com a lista e converte para inteiro
            mensagem = int('0b'+''.join(map(str,m)),2)
            #depois decidimos o que vai voltar, uma lista ou um inteiro
            if lista:
                mensagem_cifrada = bin(pow(mensagem, self._e, self._n))
                return [int(j) for j in mensagem_cifrada[2:]]
            else:
                return pow(mensagem, self._e, self._n)
        
        #checar se o numero dado foi um numero inteiro
        elif type(m) == int:
            if lista:
                mensagem_cifrada = bin(pow(m, self._e, self._n))
                return [int(j) for j in mensagem_cifrada[2:]]
            else:
                return pow(m, self._e, self._n)
        else:
            print("Escreva uma mensagem valida")
    
    def decriptRSA(self, c, lista = True):
        if type(c) == list:
            cifra = int('0b'+''.join(map(str,c)),2)
            if lista:
                volta_mensagem = bin(pow(cifra, self._d, self._n))
                return [int(i) for i in volta_mensagem[2:]]
            else:
               return pow(cifra, self._d, self._n  )
        elif type(c) == int:
            return pow(c, self._d, self._n)
        else:
            print("coloque um texto cifrado válido")
    
    def set_e(self,n=300):
        aux_var = True
        e = generate_prime_number(n)
        while aux_var:
             # generates a candidate of e
            if bgcd(e, self._phin) == 1:
                aux_var = False
                return e
            else:
                e = generate_prime_number(n)
    
    def set_d(self):
        return modinv(self._e, self._phin)
    