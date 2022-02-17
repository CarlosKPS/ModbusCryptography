# -*- coding: utf-8 -*-
"""
Created on Mon Jan 31 23:02:19 2022

@author: carlos
"""
from math import isqrt, floor
from timeit import timeit
import numpy as np

def prime_number_list(n):
    """
    This function perform a Sieve of Eratosthenes algorithm
    
    Parameters
    ----------
    n : INT
        The maximum value that will seach for prime numbers.

    Returns
    -------
    A list of all prime number less than n.

    """
    if n<=2:
        return []
    
    is_prime = [True] *n
    is_prime[0] = False
    is_prime[1] = False
    
    for i in range(2, isqrt(n)):
        if is_prime[i]:
            for x in range(i*i, n, i):
                is_prime[x] = False
                
    return [i for i in range(n) if is_prime[i]]


def prime_number_2(n):
    
    primelist = []
    
    for x in range(2, n+1):
        isPrime = True
        for y in range(2, int(x**0.5)+1):
            if x%y == 0:
                isPrime = False
                break
        if isPrime:
            primelist.append(x)
    
    return primelist



from random import randrange, getrandbits
def is_prime(n, k=128):
    """ Test if a number is prime
        Args:
            n -- int -- the number to test
            k -- int -- the number of tests to do
        return True if n is prime
    """
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


def generate_prime_candidate(length):
    """ Generate an odd integer randomly
        Args:
            length -- int -- the length of the number to generate, in bits
        return a integer
    """
    # generate random bits
    p = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=1024):
    """ Generate a prime
        Args:
            length -- int -- length of the prime to generate, in          bits
        return a prime
    """
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p

def bgcd(p,q):
    return p if q==0 else bgcd(q, p%q)



def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m


