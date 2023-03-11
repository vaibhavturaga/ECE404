#Homework Number: 04
#Name: Vaibhav Turaga
#ECN Login: vturaga
#Due Date: 2/14/2023
import sys
from BitVector import *
#gen key schedule
AES_modulus = BitVector(bitstring='100011011')
def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable
#byte substitution
AES_modulus = BitVector(bitstring='100011011')
subBytesTable = [] # SBox for encryption
invSubBytesTable = [] # SBox for decryption
def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

#shift rows
def shift_rows(arr):
    for i in range(1, 4):
        arr[i] = arr[i][i:] + arr[i][:i]
    return arr

def invshift_rows(arr):
    for i in range(1, 4):
        arr[i] = arr[i][len(arr[i])-i:] + arr[i][:len(arr[i])-i]
    return arr
def mix_columns(arr):
    #for each byte in a column:
    # replace each byte by 2 times that byte plus three times the next byte
    #plus the next byte plus the next byte
    new_arr = [[0 for x in range(4)] for x in range(4)]# [[0]*4] * 4
    
    # for i in range(4):
    #     for j in range(4):
    #         new_arr[i][j] = arr[i][j]
   
    temp0 = BitVector(hexstring = '02')
    temp1 = BitVector(hexstring = '03')
    for i in range(4):
        new_arr[0][i] = arr[0][i].gf_multiply_modular(temp0, AES_modulus, 8) ^ arr[1][i].gf_multiply_modular(temp1, AES_modulus, 8) ^ arr[2][i] ^ arr[3][i]
        new_arr[1][i] = arr[0][i] ^ arr[1][i].gf_multiply_modular(temp0, AES_modulus, 8) ^ arr[2][i].gf_multiply_modular(temp1, AES_modulus, 8) ^ arr[3][i]
        new_arr[2][i] = arr[0][i] ^ arr[1][i] ^ arr[2][i].gf_multiply_modular(temp0, AES_modulus, 8) ^ arr[3][i].gf_multiply_modular(temp1, AES_modulus, 8)
        new_arr[3][i] = arr[0][i].gf_multiply_modular(temp1, AES_modulus, 8) ^ arr[1][i] ^ arr[2][i] ^ arr[3][i].gf_multiply_modular(temp0, AES_modulus, 8)

    return new_arr

def invmix_columns(arr):
#for each byte in a column:
    # replace each byte by 2 times that byte plus three times the next byte
    #plus the next byte plus the next byte
    new_arr = [[0 for x in range(4)] for x in range(4)]# [[0]*4] * 4
    
    # for i in range(4):
    #     for j in range(4):
    #         new_arr[i][j] = arr[i][j]
   
    E = BitVector(hexstring = '0e')
    B = BitVector(hexstring = '0b')
    D = BitVector(hexstring = '0d')
    Nine = BitVector(hexstring = '09')
    for i in range(4):
        new_arr[0][i] = arr[0][i].gf_multiply_modular(E, AES_modulus, 8) ^ arr[1][i].gf_multiply_modular(B, AES_modulus, 8) ^ arr[2][i].gf_multiply_modular(D, AES_modulus, 8) ^ arr[3][i].gf_multiply_modular(Nine, AES_modulus, 8)        
        new_arr[1][i] = arr[0][i].gf_multiply_modular(Nine, AES_modulus, 8) ^ arr[1][i].gf_multiply_modular(E, AES_modulus, 8) ^ arr[2][i].gf_multiply_modular(B, AES_modulus, 8) ^ arr[3][i].gf_multiply_modular(D, AES_modulus, 8)
        new_arr[2][i] = arr[0][i].gf_multiply_modular(D, AES_modulus, 8) ^ arr[1][i].gf_multiply_modular(Nine, AES_modulus, 8) ^ arr[2][i].gf_multiply_modular(E, AES_modulus, 8) ^ arr[3][i].gf_multiply_modular(B, AES_modulus, 8)
        new_arr[3][i] = arr[0][i].gf_multiply_modular(B, AES_modulus, 8) ^ arr[1][i].gf_multiply_modular(D, AES_modulus, 8) ^ arr[2][i].gf_multiply_modular(Nine, AES_modulus, 8) ^ arr[3][i].gf_multiply_modular(E, AES_modulus, 8)
    
    # for i in range(4):
    #     print(arr[i][0].get_bitvector_in_hex() + "," + arr[i][1].get_bitvector_in_hex() + "," + arr[i][2].get_bitvector_in_hex() + "," + arr[i][3].get_bitvector_in_hex())
    # print("--------")
    # for i in range(4):
    #     print(new_arr[i][0].get_bitvector_in_hex() + "," + new_arr[i][1].get_bitvector_in_hex() + "," + new_arr[i][2].get_bitvector_in_hex() + "," + new_arr[i][3].get_bitvector_in_hex())


    return new_arr


def encrypt(message, keyfile):
    #read key from keyfile
    keybvf = BitVector(filename = keyfile)
    key_bv = keybvf.read_bits_from_file(256)

    #get key schedule
    keys = gen_key_schedule_256(key_bv)

    final_bv = BitVector(size = 0)
    for i in range(len(message) // 128):
        bv = message[i*128: (i+1) * 128]
        #add padding

        if(bv.length() > 0) and (bv.length() < 128):
            bv.pad_from_right(128 - bv.length())


        #XOR with round key -
        bv ^= (keys[0] + keys[1] + keys[2] + keys[3])
        for i in range(0, 13):
            #create state array
            statearray = [[bv[r*8 + c*32:r*8+8 + c*32] for c in range(4)] for r in range(4)]
            #sub bytes
                #use subBytesTable for encryption
            for g in range(4):
                for j in range(4):
                    statearray[g][j] = subBytesTable[int(statearray[g][j])]
                    statearray[g][j] = BitVector(intVal = statearray[g][j], size = 8)            
            #convert to bitvector

            #shift rows
            statearray = shift_rows(statearray)
            bv = BitVector(size = 0)
            for x in range(4):
                for y in range(4):
                    bv = bv + statearray[y][x]
            
            #mix columns
            statearray = mix_columns(statearray)

            #convert to bitvector
            bv = BitVector(size = 0)
            for x in range(4):
                for y in range(4):
                    bv = bv + statearray[y][x]


            #add round key
            bv ^= (keys[(i+1) * 4] + keys[(i+1) * 4 + 1] + keys[(i+1) * 4 + 2] + keys[(i + 1) * 4 + 3])


        #last round without mix columns
        #create state array
        statearray = [[bv[r*8 + c*32:r*8+8 + c*32] for c in range(4)] for r in range(4)]

        #sub bytes
            #use subBytesTable for encryption
        for g in range(4):
            for j in range(4):
                statearray[g][j] = subBytesTable[int(statearray[g][j])]
                statearray[g][j] = BitVector(intVal = statearray[g][j], size = 8)
        
        #shift rows
        statearray = shift_rows(statearray)

        #convert to bitvector
        bv = BitVector(size = 0)
        for x in range(4):
            for y in range(4):
                bv = bv + statearray[y][x]
        
        bv ^= (keys[(14) * 4] + keys[(14) * 4 + 1] + keys[(14) * 4 + 2] + keys[(14) * 4 + 3])
        final_bv += bv

    return final_bv


    #write in hexstring to encryptfile


def x931(v0, dt, totalNum, key_file):
# * Arguments:
# v0: 128-bit BitVector object containing the seed value
# dt: 128-bit BitVector object symbolizing the date and time
# totalNum: The total number of random numbers to generate
# key_file: Filename for text file containing the ASCII encryption key for AES
# * Function Description:
# This function uses the arguments with the X9.31 algorithm to generate totalNum
# random numbers as BitVector objects.
# Returns a list of BitVector objects, with each BitVector object representing a
# random number generated from X9.31.

    list_of_nums = []
    genTables()
    for i in range(totalNum):
        encrypted_dt = encrypt(dt, key_file)
        v0 ^= encrypted_dt
        encrypted_xor = encrypt(v0, key_file)

        list_of_nums.append(int(encrypted_xor))

        v0 = encrypt(encrypted_dt ^ encrypted_xor, key_file)
    
    return list_of_nums



