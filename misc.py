import utils
import cipher
import random

def detect_AES_ECB(b):
    d = dict()
    for i in range(0, len(b)):
        if b[i] not in d:
            d[b[i]] = 0
        else:
            d[b[i]] += 1
    total_repeats = 0
    for key in d:
        total_repeats += d[key]
    if (total_repeats / len(b)) > .35:
        return True
    else:
        return False
    
def detect_AES_ECB2(b):
    d = dict()
    for i in range(0, len(b)):
        if b[i] not in d:
            d[b[i]] = 0
        else:
            d[b[i]] += 1
    total_repeats = 0
    for key in d:
        total_repeats += d[key]
    if (total_repeats / len(b)) > .4:
        return True
    else:
        return False

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
        iv = bytes()
        for i in range(0, 16):
            iv += bytes([random.randint(0,255)])
        c = cipher.AES_CBC(key, iv)
        return c.encrypt(b)
    else:
        c = cipher.AES_ECB(key)
        return c.encrypt(b)

def encryption_oracle_constantKey():
    s = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    print (str(len(s)))
    b = utils.base64ToBytes(s)
    key = bytes([239, 65, 186, 36, 30, 3, 54, 73, 158, 112, 89, 138, 40, 25, 13, 81])
    c = cipher.AES_ECB(key)
    return c.encrypt(b)
