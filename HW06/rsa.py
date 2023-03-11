import sys
import random
from BitVector import *
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

def key_generation(p_txt, q_txt):
    generator = PrimeGenerator( bits = 128 )                 #(M4)
    p = generator.findPrime()
    q = generator.findPrime()
    e = 65537
    while((isSet(q) == 0) or (isSet(p) == 0) or (p == q) or gcd(p-1, e) != 1 or gcd(q - 1, e) != 1):
        q = generator.findPrime()
        p = generator.findPrime()

    
    # public_key = [e, n]
    # private_key = [d, n]

    p_file = open(p_txt, 'w')
    p_file.write(str(p))
    p_file.close()

    q_file = open(q_txt, 'w')
    q_file.write(str(q))
    q_file.close()

def encryption(message_file, p_file, q_file, encrypted_file):
    p_fp = open(p_file, 'r')
    p = p_fp.read()
    p_fp.close()

    q_fp = open(q_file, 'r')
    q = q_fp.read()
    q_fp.close()

    e = 65537
    n = int(p) * int(q)

    phi_n = (int(p) - 1) * (int(q) - 1)
    e_bv = BitVector(intVal = e)

    #d = e_bv.multiplicative_inverse(BitVector(intVal = phi_n)) 

    bv = BitVector(filename = message_file)

    enc_fp = open(encrypted_file, 'w')
    while(bv.more_to_read):
        m_bv = bv.read_bits_from_file(128)

        if m_bv.length() > 0:
            if m_bv.length() < 128:
                m_bv.pad_from_right(128-m_bv.length())
        m_bv.pad_from_left(128)

        c = pow(int(m_bv), e, n)
        c_bv = BitVector(intVal = c, size = 256)
        enc_fp.write(c_bv.get_bitvector_in_hex())



    #C = M^e mod n




def decryption(encrypted_txt, p_txt, q_txt, decrypted_txt):
    p_fp = open(p_txt, 'r')
    p = p_fp.read()
    p_fp.close()

    q_fp = open(q_txt, 'r')
    q = q_fp.read()
    q_fp.close()

    e = 65537
    n = int(p) * int(q)

    phi_n = (int(p) - 1) * (int(q) - 1)
    e_bv = BitVector(intVal = e, size = 128)

    d = int(e_bv.multiplicative_inverse(BitVector(intVal = phi_n, size = 256)))

    fp = open(encrypted_txt, 'r')
    bv = BitVector(hexstring = fp.read())

    out_fp = open(decrypted_txt, 'w')
    for i in range(bv.length() // 256):
        #read as hexstring
        c_bv = bv[i*256:(i+1) * 256]

        M = pow(int(c_bv), d, n)
        M_bv = BitVector(intVal = M, size = 256)
        M_bv = M_bv[128:256]
        out_fp.write(M_bv.get_bitvector_in_ascii())


if __name__ == "__main__":
    if sys.argv[1] == "-g":
        key_generation(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "-e":
        encryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif sys.argv[1] == "-d":
        decryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])