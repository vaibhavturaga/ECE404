import sys
import random
from BitVector import *
import math
def solve_pRoot(p, x): 
	'''
	Implement binary search to find the pth root of x. The logic is as follows:
	1). Initialize upper bound to 1
	2). while u^p <= x, increment u by itself
	3). Intialize lower bound to u//2
	4). While the lower bound is smaller than the upper bound:
        a). Compute the midpoint as (lower + upper) / 2
        b). Exponentiate the midpoint by p
        c). if lower bound < midpoint and midpoint < x, then set the new lower bound to midpoint
        d). else if upperbown > midpoint and midpoint > x, then set the new upper bown to midpoint
        e). else return the midpoint
	5). If while loop breaks before returning, return midpoint + 1

	Author: Joseph Wang
		wang3450 at purdue edu

	'''

	u = 1
	while u ** p <= x: u *= 2

	l = u // 2
	while l < u:
		mid = (l + u) // 2
		mid_pth = mid ** p
		if l < mid and mid_pth < x:
			l = mid
		elif u > mid and mid_pth > x:
			u = mid
		else:
			return mid
	return mid + 1
class PrimeGenerator( object ):                                              #(A1)
    def __init__( self, **kwargs ):                                          #(A2)
        bits = debug = None                                                  #(A3)
        if 'bits' in kwargs  :     bits = kwargs.pop('bits')                 #(A4)
        if 'debug' in kwargs :     debug = kwargs.pop('debug')               #(A5)
        self.bits            =     bits                                      #(A6)
        self.debug           =     debug                                     #(A7)
        self._largest        =     (1 << bits) - 1                           #(A8)

    def set_initial_candidate(self):                                         #(B1)
        candidate = random.getrandbits( self.bits )                          #(B2)
        if candidate & 1 == 0: candidate += 1                                #(B3)
        candidate |= (1 << self.bits-1)                                      #(B4)
        candidate |= (2 << self.bits-3)                                      #(B5)
        self.candidate = candidate                                           #(B6)

    def set_probes(self):                                                    #(C1)
        self.probes = [2,3,5,7,11,13,17]                                     #(C2)

    # This is the same primality testing function as shown earlier
    # in Section 11.5.6 of Lecture 11:
    def test_candidate_for_prime(self):                                      #(D1)
        'returns the probability if candidate is prime with high probability'
        p = self.candidate                                                   #(D2)
        if p == 1: return 0                                                  #(D3)
        if p in self.probes:                                                 #(D4)
            self.probability_of_prime = 1                                    #(D5)
            return 1                                                         #(D6)
        if any([p % a == 0 for a in self.probes]): return 0                  #(D7)
        k, q = 0, self.candidate-1                                           #(D8)
        while not q&1:                                                       #(D9)
            q >>= 1                                                          #(D10)
            k += 1                                                           #(D11)
        if self.debug: print("q = %d  k = %d" % (q,k))                       #(D12)
        for a in self.probes:                                                #(D13)
            a_raised_to_q = pow(a, q, p)                                     #(D14)
            if a_raised_to_q == 1 or a_raised_to_q == p-1: continue          #(D15)
            a_raised_to_jq = a_raised_to_q                                   #(D16)
            primeflag = 0                                                    #(D17)
            for j in range(k-1):                                             #(D18)
                a_raised_to_jq = pow(a_raised_to_jq, 2, p)                   #(D19)
                if a_raised_to_jq == p-1:                                    #(D20)
                    primeflag = 1                                            #(D21)
                    break                                                    #(D22)
            if not primeflag: return 0                                       #(D23)
        self.probability_of_prime = 1 - 1.0/(4 ** len(self.probes))          #(D24)
        return self.probability_of_prime                                     #(D25)

    def findPrime(self):                                                     #(E1)
        self.set_initial_candidate()                                         #(E2)
        if self.debug:  print("    candidate is: %d" % self.candidate)       #(E3)
        self.set_probes()                                                    #(E4)
        if self.debug:  print("    The probes are: %s" % str(self.probes))   #(E5)
        max_reached = 0                                                      #(E6)
        while 1:                                                             #(E7)
            if self.test_candidate_for_prime():                              #(E8)
                if self.debug:                                               #(E9)
                    print("Prime number: %d with probability %f\n" %       
                          (self.candidate, self.probability_of_prime) )      #(E10)
                break                                                        #(E11)
            else:                                                            #(E12)
                if max_reached:                                              #(E13)
                    self.candidate -= 2                                      #(E14)
                elif self.candidate >= self._largest - 2:                    #(E15)
                    max_reached = 1                                          #(E16)
                    self.candidate -= 2                                      #(E17)
                else:                                                        #(E18)
                    self.candidate += 2                                      #(E19)
                if self.debug:                                               #(E20)
                    print("    candidate is: %d" % self.candidate)           #(E21)
        return self.candidate                                                #(E22)

def gcd(a, b):
    while b:                                             
        a,b = b, a%b
    return a
def isSet(a):
    a_bv = BitVector(intVal = a)
    if a_bv[0] == 1:
        if a_bv[1] == 1:
            return 1
    return 0

def key_generation():
    generator = PrimeGenerator( bits = 128 )                 #(M4)
    p = generator.findPrime()
    q = generator.findPrime()
    e = 3
    while((isSet(q) == 0) or (isSet(p) == 0) or (p == q) or gcd(p-1, e) != 1 or gcd(q - 1, e) != 1):
        q = generator.findPrime()
        p = generator.findPrime()

    return p, q

def encryption(message_file, enc1_txt, enc2_txt, enc3_txt, n_1_2_3_txt):
    n_list = []
    
    enc_fp = [open(enc1_txt, 'w'), open(enc2_txt, 'w'), open(enc3_txt, 'w')]
    e = 3
    #e_bv = BitVector(intVal = e)
    for i in range(3):
        p, q = key_generation()
        n = int(p) * int(q)
        n_list.append(n)
        phi_n = (int(p) - 1) * (int(q) - 1)
        bv = BitVector(filename = message_file)

        while(bv.more_to_read):
            m_bv = bv.read_bits_from_file(128)

            if len(m_bv) > 0:
                if len(m_bv) < 128:
                    m_bv.pad_from_right(128-len(m_bv))

            c = int(pow(int(m_bv), e, n))
            c_bv = BitVector(intVal = c, size = 256)
            enc_fp[i].write(c_bv.get_bitvector_in_hex())
    #print(n_list[0],n_list[1],n_list[2])
    n_fp = open(n_1_2_3_txt, 'w')
    n_fp.write(str(n_list[0]))
    n_fp.write('\n')
    n_fp.write(str(n_list[1]))
    n_fp.write('\n')
    n_fp.write(str(n_list[2]) + "\n")
    n_fp.close()


def decryption(enc1_txt, enc2_txt, enc3_txt, n_1_2_3_txt, cracked_txt):
    n_fp = open(n_1_2_3_txt, 'r')
    n1 = int(n_fp.readline())
    n2 = int(n_fp.readline())
    n3 = int(n_fp.readline())

    N_prod = int(n1 * n2 * n3)

    fp1 = open(enc1_txt, 'r')
    bv1 = BitVector(hexstring = fp1.read())
    fp2 = open(enc2_txt, 'r')
    bv2 = BitVector(hexstring = fp2.read())
    fp3 = open(enc3_txt, 'r')
    bv3 = BitVector(hexstring = fp3.read())

    capN1 = n2 * n3
    c1 = int(BitVector(intVal = capN1).multiplicative_inverse(BitVector(intVal = n1))) * capN1
    
    capN2 = n1 * n3
    c2 = int(BitVector(intVal = capN2).multiplicative_inverse(BitVector(intVal = n2))) * capN2

    capN3 = n1 * n2
    c3 = int(BitVector(intVal = capN3).multiplicative_inverse(BitVector(intVal = n3))) * capN3
    print(c1,c2,c3)
    crack_enc = open(cracked_txt, 'w')
    for i in range(len(bv1) // 256):
        #read as hexstring
        c_bv1 = bv1[i*256:(i+1) * 256]
    
        #read as hexstring
        c_bv2 = bv2[i*256:(i+1) * 256]

        #read as hexstring
        c_bv3 = bv3[i*256:(i+1) * 256]

        M3 = c1 * int(c_bv1) + c2 * int(c_bv2) + c3 * int(c_bv3)
        
        M = solve_pRoot(3, M3 % N_prod)
        crack_enc.write(BitVector(intVal = M, size = 256)[128:].get_bitvector_in_ascii())

if __name__ == "__main__":
    if sys.argv[1] == "-e":
        encryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    
    if sys.argv[1] == "-c":
        decryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
