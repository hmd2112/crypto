import utils
from Crypto.Cipher import AES

class SingleByte_XOR:
    def __init__(self, key):
        self.key = key
    def encrypt(self, data):
        encrypted_data_ba = bytearray()
        for i in range(0, len(data)):
            encrypted_data_ba.append(data[i] ^ self.key)
        return bytes(encrypted_data_ba)
    def decrypt(self, data):
        return self.encrypt(data)

class RepeatingKey_XOR:
    def __init__(self, key):
        self.key = key
        self.key_length = len(key)
    def encrypt(self, data):
        encrypted_data_ba = bytearray()
        key_index = 0
        for i in range(0, len(data)):
            encrypted_data_ba.append(data[i] ^ self.key[key_index])
            key_index = (key_index + 1) % self.key_length
        return bytes(encrypted_data_ba)
    def decrypt(self, data):
        return self.encrypt(data)

class AES_ECB:
    def __init__(self, key):
        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)
    def encrypt(self, data):
        return self.cipher.encrypt(data)
    def decrypt(self, data):
        return self.cipher.decrypt(data)

class AES_CBC:
    def __init__(self, key, iv):
        self.key = key
        self.keysize = len(key)
        self.iv = iv
        if len(key) != len(iv):
            raise ValueError('key length and iv length do not match')
        self.cipher = AES.new(key, AES.MODE_ECB)
    def encrypt(self, data):
        encrypted_data = bytes()
        cipher_text_block = self.iv
        for i in range(0, len(data), self.keysize):
            encrypted_bytes = self.cipher.encrypt(utils.XOR(data[i:i + self.keysize], cipher_text_block))
            encrypted_data += encrypted_bytes
            cipher_text_block = encrypted_bytes
        return encrypted_data
    def decrypt(self, data):
        decrypted_data = bytes()
        cipher_text_block = self.iv
        for i in range(0, len(data), self.keysize):
            decrypted_bytes = self.cipher.decrypt(data[i:i + self.keysize])
            decrypted_data += utils.XOR(decrypted_bytes, cipher_text_block)
            cipher_text_block = data[i:i + self.keysize]
        return decrypted_data

