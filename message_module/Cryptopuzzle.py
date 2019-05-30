#Put in Repo: (-1/(argument+1) + 1) * 10**8


def crypto_challenge(argument):
    new_number = (-1/((argument/4)+1) + 1) * 10**7

    buff = 0
    for i in range(0, int(new_number)):
        buff += 1
    return buff

def calc_result(argument):
    return int((-1 / ((argument / 4) + 1) + 1) * 10 ** 7)

import random


def cryptopuzzle(arg, param):
    n = random.getrandbits(arg)
    while bin(n).count("1") > param:
        n = random.getrandbits(arg)
    return n

def check_crypto(result, param):
    binar = bin(result)
    return not binar.count("1") > param

