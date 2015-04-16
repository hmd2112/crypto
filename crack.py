import utils
import cipher

def crack_SingleByte_XOR(b):
    d = dict()
    for xor_byte in range(0, 256):
        ba = bytearray()
        for byte in b:
            ba.append(byte ^ xor_byte)
        new_b = bytes(ba)
        d[xor_byte] = new_b

    score_list = []
    
    for key in d:
        score = 0
        plain_text = ''
        try:
            plain_text = bytes(d[key]).decode(encoding='utf-8')
        except:
            continue
        score = utils.score_str(plain_text)
        score_list.append([score, key, plain_text])
        
    score_list.sort()
    return score_list

def crack_RepeatingByte_XOR(b):
    #Calculate possible keysize using hamming distance
    hamming_list = []
    for keysize in range(2, 41):
        h_total = 0
        h_total_dist = 0
        for offset in range(0, len(b) - keysize * 2, keysize):
            b1 = b[offset:offset + keysize]
            ba1 = bytearray(b1)
            b2 = b[offset + keysize:offset + keysize * 2]
            ba2 = bytearray(b2)

            h_total_dist += utils.hamming_distance(ba1, ba2) / keysize
            h_total += 1
        h_avg = h_total_dist / h_total
        hamming_list.append([h_avg, keysize])
    hamming_list.sort()
    possible_key_size = hamming_list[0][1]
##    for i in range(0,5):
##        print (str(hamming_list[i][1]))
##    print ('Possible keysize: ' + str(possible_key_size))

    #Determine key from possible key size
    index = 0
    segmented_content = []
    segmented_score_list = []
    for i in range(0, possible_key_size):
        segmented_content.append([])
        segmented_score_list.append([])
    for byte in b:
        segmented_content[index].append(byte)
        index = (index + 1) % possible_key_size

    for i in range(0, possible_key_size):
        segmented_score_list[i] = crack_SingleByte_XOR(segmented_content[i])

##    for score_list in segmented_score_list:
##        for i in range(0,3):
##            print (str(score_list[i][0]) + '\t' + chr(score_list[i][1]) + '\t' + score_list[i][2][:40])
##        print ()

    #Build key. Take highest score for each segment from crack_SingleByte_XOR
    key_ba = bytearray()
    for j in range(0, possible_key_size):
        key_ba.append(segmented_score_list[j][0][1])
##    print (str(key_ba))
    
    rk_xor_cipher = cipher.RepeatingKey_XOR(bytes(key_ba))
    return rk_xor_cipher.decrypt(b)
