from AES_image import ctr_aes_image
from BitVector import *
iv = BitVector(textstring = 'computersecurity')
ctr_aes_image(iv, 'image.ppm', 'enc_image1.ppm', 'keyCTR.txt')