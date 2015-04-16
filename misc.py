import utils
import cipher
import random

def block_repeats(block_size, s):
    byte16_dict = dict()
    first_index = 0
    second_index = block_size
    while second_index < len(s):
        segment = s[first_index:second_index]
        if segment not in byte16_dict:
            byte16_dict[segment] = 0
        else:
            byte16_dict[segment] += 1
        first_index = second_index
        second_index += block_size
    num_repeats = 0
    for key in byte16_dict:
        num_repeats += byte16_dict[key]
    return num_repeats

def encryption_oracle(b):
    prefix = bytes()
    for i in range(0, random.randint(5, 10)):
        prefix += bytes([random.randint(0,255)])
    suffix = bytes()
    for i in range(0, random.randint(5, 10)):
        suffix += bytes([random.randint(0,255)])
    for i in range(0, 16 - (len(prefix + b + suffix) % 16) % 16):
        suffix += bytes([random.randint(0,255)])
    b = prefix + b + suffix
    useCBC = random.randint(0, 1)
    key = bytes()
    for i in range(0,16):
        key += bytes([random.randint(0,255)])
    if useCBC == 0:
##        print ('encryption_oracle using CBC (internal)')
        iv = bytes()
        for i in range(0, 16):
            iv += bytes([random.randint(0,255)])
        c = cipher.AES_CBC(key, iv)
        return c.encrypt(b)
    else:
##        print ('encryption_oracle using ECB (internal)')
        c = cipher.AES_ECB(key)
        return c.encrypt(b)

def encryption_oracle_constantKey(new_b):
    s = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    b = utils.base64ToBytes(s)
    contents = new_b + b
    contents = utils.pkcs_pad(contents, 16)
    key = bytes([239, 65, 186, 36, 30, 3, 54, 73, 158, 112, 89, 138, 40, 25, 13, 81])
    c = cipher.AES_ECB(key)
    return c.encrypt(contents)
