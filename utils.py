hex_CA = '0123456789abcdef'
base64_CA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
base64_IA = [-1] * 256
for i in range(0, len(base64_CA)):
    base64_IA[ord(base64_CA[i])] = i
base64_IA[ord('=')] = 0

letter_frequency = dict()
letter_frequency['a'] = 8.167
letter_frequency['b'] = 1.492
letter_frequency['c'] = 2.782
letter_frequency['d'] = 4.253
letter_frequency['e'] = 12.702
letter_frequency['f'] = 2.228
letter_frequency['g'] = 2.015
letter_frequency['h'] = 6.094
letter_frequency['i'] = 6.966
letter_frequency['j'] = 0.153
letter_frequency['k'] = 0.772
letter_frequency['l'] = 4.025
letter_frequency['m'] = 2.406
letter_frequency['n'] = 6.749
letter_frequency['o'] = 7.507
letter_frequency['p'] = 1.929
letter_frequency['q'] = 0.095
letter_frequency['r'] = 5.987
letter_frequency['s'] = 6.327
letter_frequency['t'] = 9.056
letter_frequency['u'] = 2.758
letter_frequency['v'] = 0.978
letter_frequency['w'] = 2.360
letter_frequency['x'] = 0.150
letter_frequency['y'] = 1.974
letter_frequency['z'] = 0.074

##dictionary = []
##f = open ('ospd.txt', 'r')
##for line in f:
##    line = line.replace('\n', '')
##    line = line.replace('\r', '')
##    dictionary.append(line)
##f.close()

def hexToInt(hexChar):
    hexChar = hexChar.lower()
    if hexChar == '0':
        return 0
    elif hexChar == '1':
        return 1
    elif hexChar == '2':
        return 2
    elif hexChar == '3':
        return 3
    elif hexChar == '4':
        return 4
    elif hexChar == '5':
        return 5
    elif hexChar == '6':
        return 6
    elif hexChar == '7':
        return 7
    elif hexChar == '8':
        return 8
    elif hexChar == '9':
        return 9
    elif hexChar == 'a':
        return 10
    elif hexChar == 'b':
        return 11
    elif hexChar == 'c':
        return 12
    elif hexChar == 'd':
        return 13
    elif hexChar == 'e':
        return 14
    elif hexChar == 'f':
        return 15
    else:
        return -1

def hexToBytes(hexStr):
    #b = bytes.fromhex(hexStr)
    length = len(hexStr)
    if length % 2 != 0:
        raise ValueError('Hex string has an odd number of characters')
    index = 0
    ba = bytearray()
    while index < length:
        c1 = hexToInt(hexStr[index])
        c2 = hexToInt(hexStr[index + 1])
        if c1 < 0:
            raise ValueError('Invalid hex character \'' + hexStr[index] + '\'')
        if c2 < 0:
            raise ValueError('Invalid hex character \'' + hexStr[index + 1] + '\'')
        temp = 0
        temp = temp | (c1 << 4)
        temp = temp | c2
        ba.append(temp)
        index += 2
    return bytes(ba)

def bytesToHex(b):
    hexStr = ''
    for byte in b:
        hexStr += hex_CA[(byte & 0xF0) >> 4]
        hexStr += hex_CA[byte & 0x0F]
    return hexStr

def base64ToBytes(base64_str):
    ba = bytearray()
    length = len(base64_str)
    if (length % 4) != 0:
        raise ValueError('Invalid base64 string')
    index = 0
    while index < length:
        c1 = base64_str[index]
        c2 = base64_str[index + 1]
        c3 = base64_str[index + 2]
        c4 = base64_str[index + 3]

        ba.append(((base64_IA[ord(c1)] << 2) | (base64_IA[ord(c2)] >> 4)) & 0xFF)
        ba.append(((base64_IA[ord(c2)] << 4) | (base64_IA[ord(c3)] >> 2)) & 0xFF)
        ba.append(((base64_IA[ord(c3)] << 6) | (base64_IA[ord(c4)])) & 0xFF)
        
        index += 4
     
    return bytes(ba)

def bytesToBase64(b):
    #import base64
    #base64Str = base64.b64encode(b)
    base64_str = ''
    index = 0
    length = len(b)
    while index < length:
        if (length - index) > 2:
            base64_str += addChunk(b[index], b[index + 1], b[index + 2], 0)
        elif (length - index) == 2:
            base64_str += addChunk(b[index], b[index + 1], 0, 1)
        else:
            base64_str += addChunk(b[index], 0, 0, 2)
        index += 3
    return base64_str

def addChunk(c1, c2, c3, pads):
    chars = []
    chars.append(base64_CA[c1 >> 2])
    chars.append(base64_CA[((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4)])
    if pads == 2:
        chars.append('=')
        chars.append('=')
    elif pads == 1:
        chars.append(base64_CA[((c2 & 0x0F) << 2) | ((c3 & 0xC0) >> 6)])
        chars.append('=')
    else:
        chars.append(base64_CA[((c2 & 0x0F) << 2) | ((c3 & 0xC0) >> 6)])
        chars.append(base64_CA[(c3 & 0x3F)])
    return ''.join(chars)

def score_str(s):
    s = s.lower()
    score = 0
    length = len(s)
    d = dict()
    for char in s:
        if char not in d:
            d[char] = 1
        else:
            d[char] += 1
            
    for char in letter_frequency:
        if char not in d:
            score += letter_frequency[char]
        else:
            freq = d[char] / length * 100
            score += abs(freq - letter_frequency[char])

    # Add points if we have non alpha characters
    for char in d:
        if char == ' ':
            continue
        if char not in letter_frequency:
            score += d[char] / length * 100

    return score

def hamming_distance(ba1, ba2):
    length = len(ba1)
    count = 0
    for i in range(0, length):
        if (ba1[i] ^ ba2[i]) & 0x01:
            count += 1
        if (ba1[i] ^ ba2[i]) & 0x02:
            count += 1
        if (ba1[i] ^ ba2[i]) & 0x04:
            count += 1
        if (ba1[i] ^ ba2[i]) & 0x08:
            count += 1
        if (ba1[i] ^ ba2[i]) & 0x10:
            count += 1
        if (ba1[i] ^ ba2[i]) & 0x20:
            count += 1
        if (ba1[i] ^ ba2[i]) & 0x40:
            count += 1
        if (ba1[i] ^ ba2[i]) & 0x80:
            count += 1
    return count

def XOR(b1, b2):
    if len(b1) != len(b2):
        return None
    xor_bytes = bytearray()
    for i in range(0, len(b1)):
        xor_bytes.append(b1[i] ^ b2[i])
    return bytes(xor_bytes)

def pkcs_pad(b, pad):
    num_to_add = pad - (len(b) % pad)
    if num_to_add < 0:
        return None
    b += bytes([num_to_add] * num_to_add)
    return b
