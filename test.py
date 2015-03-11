import cipher
import utils
import misc

s= 'A'*128
encrypted_contents = misc.encryption_oracle_constantKey()
print (str(len(encrypted_contents)))
print (str(encrypted_contents))
print (misc.detect_AES_ECB(encrypted_contents))
