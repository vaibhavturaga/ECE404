from BitVector import *
def cryptBreak(ciphertextFile, key_bv):
    file = open(ciphertextFile, "r")
    ciphertext = file.read()
    file.close()
    passphrase = "Hopes and dreams of a million years" #used for initilaization vector for dif xor
    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8

    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
    for i in range(0, len(passphrase)):
        textstr = passphrase[i*numbytes:(i+1)*numbytes]
        bv_iv ^= BitVector( textstring = textstr)

    #create a bitvector from the ciphertext hex string
    encrypted_bv = BitVector( hexstring = ciphertext)

    #run decryption using key_bv
    msg_decrypted_bv = BitVector( size = 0 )  

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv #(U)
    for i in range(0, len(encrypted_bv) // BLOCKSIZE): #(V)
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE] #(W)
        temp = bv.deep_copy() #(X)
        bv ^= previous_decrypted_block #(Y)
        previous_decrypted_block = temp 
        bv ^= key_bv #(a)
        msg_decrypted_bv += bv
    outputtext = msg_decrypted_bv.get_text_from_bitvector() #(c)

    return outputtext


#for x in range(2**16):
#    outputtext = cryptBreak('file.txt', BitVector(intVal = x, size = 16))
#    if 'Sir Lewis' in outputtext:
#        print('Encryption Broken')
#        print(outputtext)
#        break
#    print(x)
#

print(cryptBreak('file.txt', BitVector(intVal = 4040, size = 16)))