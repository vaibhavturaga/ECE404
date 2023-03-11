#!/usr/bin/env python

## FindMI.py

import sys

if len(sys.argv) != 3:  
    sys.stderr.write("Usage: %s   <integer>   <modulus>\n" % sys.argv[0]) 
    sys.exit(1) 

NUM, MOD = int(sys.argv[1]), int(sys.argv[2])

def bit_mult(a, b):
    output = 0
    while b > 0:
        # if b is odd
        if(b & 1):
            output += a
        #divides b by 2 and multiplies a * 2
        a = a << 1
        b = b >> 1

    return output

def bit_div(a, b):
    if(a < b):
        return 0
    
    output = 0
    power = 32
    while power >= 0:
        if (b<<power) <= a:
            a = a - (b << power)
            output = output + (1 << power)
    
        power = power - 1


    return output
def MI(num, mod):
    '''
    This function uses ordinary integer arithmetic implementation of the
    Extended Euclid's Algorithm to find the MI of the first-arg integer
    vis-a-vis the second-arg integer.
    '''
    NUM = num; MOD = mod
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        q = bit_div(num, mod)
        num, mod = mod, num % mod
        x, x_old = x_old - bit_mult(q, x), x
        y, y_old = y_old - bit_mult(q, y), y
    if num != 1:
        print("\nNO MI. However, the GCD of %d and %d is %u\n" % (NUM, MOD, num))
    else:
        MI = (x_old + MOD) % MOD
        print("\nMI of %d modulo %d is: %d\n" % (NUM, MOD, MI))


MI(NUM, MOD)

