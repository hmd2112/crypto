import utils
import cipher
import misc
import crack

def c1():
    s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    ans = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    b = utils.hexToBytes(s)
    my_ans = utils.bytesToBase64(b)
    if (my_ans == ans):
        print ('c1: PASS')
    else:
        print ('c1: FAIL')

def c2():
    s = '1c0111001f010100061a024b53535009181c'
    s2 = '686974207468652062756c6c277320657965'
    ans = '746865206b696420646f6e277420706c6179'
    b = utils.hexToBytes(s)
    b2 = utils.hexToBytes(s2)
    my_ans = utils.bytesToHex(utils.XOR(b, b2))
    if (my_ans == ans):
        print ('c2: PASS')
    else:
        print ('c2: FAIL')

def c3():
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    b = utils.hexToBytes(s)
    lst = crack.crack_SingleByte_XOR(b)
##    for i in lst[:5]:
##        print (str(i))
    print ('c3: PASS (' + lst[0][2] + ')')

def c4():
    f = open('challengeFiles/4.txt', 'r')
    lines = []
    for line in f:
        line = line.replace('\r', '')
        line = line.replace('\n', '')
        lines.append(line)
    f.close()

    high_score = 1000
    high_score_str = ''
    for line in lines:
        score = 0
##        print ('Cracking line: ' + line)
        b = utils.hexToBytes(line)
        cracked_list = crack.crack_SingleByte_XOR(b)
        if len(cracked_list) <= 0:
            continue
        cracked_line = cracked_list[0][2]
        score = cracked_list[0][0]
        if score < high_score:
            high_score = score
            high_score_str = cracked_line
    high_score_str = high_score_str.replace('\n', '')
    print ('c4: PASS (' + high_score_str + ')')

def c5():
    s = """Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"""
    key = 'ICE'
    ans = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    b_key = bytes(key.encode('utf-8'))
    rk_xor_cipher = cipher.RepeatingKey_XOR(b_key)
    b = bytes(s.encode('utf-8'))
    my_ans = utils.bytesToHex(rk_xor_cipher.encrypt(b))
    if (my_ans == ans):
        print ('c5: PASS')
    else:
        print ('c5: FAIL')

def c6():
    f = open('challengeFiles/6.txt', 'r', encoding='ascii')
    base64_contents = ''
    for line in f:
        line = line.replace('\n', '')
        line = line.replace('\r', '')
        base64_contents += line
    b = utils.base64ToBytes(base64_contents)
    decrypted_contents = crack.crack_RepeatingByte_XOR(b)
##    print (decrypted_contents)
    print ('c6: PASS')

def c7():
    f = open('challengeFiles/7.txt', 'r', encoding='ascii')
    base64_contents = ''
    for line in f:
        line = line.replace('\n', '')
        line = line.replace('\r', '')
        base64_contents += line
    b = utils.base64ToBytes(base64_contents)
    key = 'YELLOW SUBMARINE'
    b_key = bytes(key.encode('utf-8'))
    aes_ecb_cipher = cipher.AES_ECB(b_key)
    decrypted_contents = aes_ecb_cipher.decrypt(b)
##    print (decrypted_contents)
    print ('c7: PASS')

def c8():
    f = open('challengeFiles/8.txt', 'r', encoding='ascii')
    hex_contents = []
    for line in f:
        line = line.replace('\n', '')
        line = line.replace('\r', '')
        hex_contents.append(line)
    f.close()

    line_number = 1
    line_repeats = []
    for line in hex_contents:
        num_repeats = misc.block_repeats(32, line)
        line_repeats.append([num_repeats, line_number])
        line_number += 1
        
    line_repeats.sort(reverse=True)
##    for i in range(0, 5):
##        print (str(line_repeats[i]))
    print ('c8: PASS (line ' + str(line_repeats[0][1]) + ', ' + str(line_repeats[0][0]) + ' repeated blocks)')

def c9():
    key = 'YELLOW SUBMARINE'
    ans = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    b_key = bytes(key.encode('utf-8'))
    my_ans = utils.pkcs_pad(b_key, 20)
    if (my_ans == ans):
        print ('c9: PASS')
    else:
        print ('c9: FAIL')

def c10():
    f = open('challengeFiles/10.txt', 'r', encoding='ascii')
    base64_contents = ''
    for line in f:
        line = line.replace('\n', '')
        line = line.replace('\r', '')
        base64_contents += line
    b = utils.base64ToBytes(base64_contents)
    b_key = b'YELLOW SUBMARINE'
    b_iv = b'\x00'*len(b_key)
    aes_cbc_cipher = cipher.AES_CBC(b_key, b_iv)
    decrypted_contents = aes_cbc_cipher.decrypt(b)
##    print (decrypted_contents)
    print ('c10: PASS')

def c11():
    b_input = bytes(('A'*100).encode('utf-8'))
    encrypted_contents = misc.encryption_oracle(b_input)
##    if misc.block_repeats(16, encrypted_contents) > 0:
##        print ('ECB')
##    else:
##        print ('CBC')
    print ('c11: PASS')

def c12():
    #Determine block size
    b = b''
    base = len(misc.encryption_oracle_constantKey(b))
    new_size = base
    while new_size == base:
        b = b + b'A'
        new_size = len(misc.encryption_oracle_constantKey(b))
    block_size = new_size - base

    #Detect if function is using EBC
    encrypted_contents = misc.encryption_oracle_constantKey(bytes(b'A'*base))
##    if misc.block_repeats(block_size, encrypted_contents) == 0:
##        print ('Using ECB')
##    else:
##        print ('Using CBC, exiting...')
##        return None
    
    #Crack one byte at a time
    b = b'A' * (base * 2 + (base % block_size))
    end = len(b) - block_size
    plain_text = b''
    encrypted_contents = misc.encryption_oracle_constantKey(b)
    while end + block_size <= len(encrypted_contents):
        b = b[1:]
        d = dict()
        for byte in range(0, 256):
            d[misc.encryption_oracle_constantKey(b + bytes([byte]))[end:end + block_size]] = byte
        encrypted_contents = misc.encryption_oracle_constantKey(b)
        plain_text += bytes([d[encrypted_contents[end:end + block_size]]])
        print (plain_text)
    print ('c12: FAIL')

def main():
##    c1()
##    c2()
##    c3()
##    c4()
##    c5()
##    c6()
##    c7()
##    c8()
##    c9()
##    c10()
##    c11()
    c12()

if __name__ == '__main__':
    main()
