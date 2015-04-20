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

def kv_parse(s):
    lst = s.split('&')
    d = dict()
    for i in lst:
        nv = i.split('=')
        if nv[0] not in d:
            d[nv[0]] = nv[1]
    return d

def profile_for_attacker(email, key):
    profile = profile_for(email)
    return encrypt_profile(profile, key)

def profile_for(email):
    email = email.replace('=', '')
    email = email.replace('&', '')
    return 'email=' + email + '&uid=10&role=user'

def encrypt_profile(profile, key):
    profile = utils.pkcs_pad(profile.encode('utf-8'), 16)
    c = cipher.AES_ECB(key)
    return c.encrypt(profile)

def decrypt_profile(encrypted_profile, key):
    c = cipher.AES_ECB(key)
    decrypted_profile = c.decrypt(encrypted_profile)
    profile = decrypted_profile
    pad = decrypted_profile[-1]
    if pad >= 0 and pad <= 15:
        profile = decrypted_profile[:len(profile) - pad]
    return profile

def encryption_oracle_constantKey2(new_b):
    s = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    b = utils.base64ToBytes(s)
    prefix = utils.generate_random(random.randint(0, 128)) # So there is a couple block size variations
    #contents = prefix + new_b + b
    contents = new_b + b
    contents = utils.pkcs_pad(contents, 16)
    key = bytes([239, 65, 186, 36, 30, 3, 54, 73, 158, 112, 89, 138, 40, 25, 13, 81])
    c = cipher.AES_ECB(key)
    return c.encrypt(contents)
