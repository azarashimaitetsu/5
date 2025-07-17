import random
from math import gcd, ceil, log
from gmssl import sm3


def int_to_bytes(x, k): 
    if pow(256, k) <= x:
        raise Exception("无法实现整数到字节串的转换，目标字节串长度过短！")
    s = hex(x)[2:].rjust(k*2, '0')
    M = b''
    for i in range(k):
        M = M + bytes([eval('0x' + s[i*2:i*2+2])])
    return M



def bytes_to_int(M): 
    k = len(M)    
    x = 0    
    for i in range(k-1, -1, -1):
        x += pow(256, k-1-i) * M[i]
    return x


def bits_to_bytes(s):           
    k = ceil(len(s)/8)        
    s = s.rjust(k*8, '0') 
    M = b'' 
    for i in range(k):
        M = M + bytes([eval('0b' + s[i*8: i*8+8])])
    return M



def bytes_to_bits(M):  
    s_list = []
    for i in M:
        s_list.append(bin(i)[2:].rjust(8, '0'))     
    s = ''.join(s_list)
    return s


def fielde_to_bytes(e):
    q = eval('0x' + '8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3'.replace(' ', ''))
    t = ceil(log(q, 2))
    l = ceil(t / 8)
    return int_to_bytes(e, l)


def bytes_to_fielde(M):    
    return bytes_to_int(M)


def fielde_to_int(a):    
    return a


def point_to_bytes(P):
    xp, yp = P[0], P[1]
    x = fielde_to_bytes(xp)
    y = fielde_to_bytes(yp)
    PC = bytes([0x04])
    s = PC + x + y
    return s


def bytes_to_point(s):
    if len(s) % 2 == 0:
        raise Exception("无法实现字节串到点的转换，请检查字节串是否为未压缩形式！")
    l = (len(s) - 1) // 2
    PC = s[0]
    if PC != 4:
        raise Exception("无法实现字节串到点的转换，请检查PC是否为b'04'！")
    x = s[1: l+1]
    y = s[l+1: 2*l+1]
    xp = bytes_to_fielde(x)
    yp = bytes_to_fielde(y)
    P = (xp, yp)  
    return P


def fielde_to_bits(a):
    a_bytes = fielde_to_bytes(a)
    a_bits = bytes_to_bits(a_bytes)
    return a_bits


def point_to_bits(P):
    p_bytes = point_to_bytes(P)
    p_bits = bytes_to_bits(p_bytes)
    return p_bits



def int_to_bits(x):
    x_bits = bin(x)[2:]
    k = ceil(len(x_bits)/8)       
    x_bits = x_bits.rjust(k*8, '0')
    return x_bits



def bytes_to_hex(m):
    h_list = [] 
    for i in m:
        e = hex(i)[2:].rjust(2, '0')    
        h_list.append(e)
    h = ''.join(h_list)
    return h



def bits_to_hex(s):
    s_bytes = bits_to_bytes(s)
    s_hex = bytes_to_hex(s_bytes)
    return s_hex



def hex_to_bits(h):
    b_list = []
    for i in h:
        b = bin(eval('0x' + i))[2:].rjust(4, '0')  
        b_list.append(b)
    b = ''.join(b_list)
    return b



def hex_to_bytes(h):
    h_bits = hex_to_bits(h)
    h_bytes = bits_to_bytes(h_bits)
    return h_bytes



def fielde_to_hex(e):
    h_bytes = fielde_to_bytes(e)
    h = bytes_to_hex(h_bytes)
    return h



def KDF(Z, klen):
    v = 256   
    if klen >= (pow(2, 32) - 1) * v:
        raise Exception("密钥派生函数KDF出错，请检查klen的大小！")
    ct = 0x00000001
    if klen % v == 0:
        l = klen // v
    else:
        l = klen // v + 1
    Ha = []
    for i in range(l): 
        s = Z + int_to_bits(ct).rjust(32, '0')  
        s_bytes = bits_to_bytes(s)  
        s_list = [i for i in s_bytes]
        hash_hex = sm3.sm3_hash(s_list)
        hash_bin = hex_to_bits(hash_hex)
        Ha.append(hash_bin)
        ct += 1
    if klen % v != 0:
        Ha[-1] = Ha[-1][:klen - v*(klen//v)]
    k = ''.join(Ha)
    return k



def calc_inverse(M, m):
    if gcd(M, m) != 1:
        return None
    u1, u2, u3 = 1, 0, M
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m



def frac_to_int(up, down, p):
    num = gcd(up, down)
    up //= num
    down //= num    
    return up * calc_inverse(down, p) % p



def add_point(P, Q, p):
    if P == 0:
        return Q
    if Q == 0:
        return P
    x1, y1, x2, y2 = P[0], P[1], Q[0], Q[1]
    e = frac_to_int(y2 - y1, x2 - x1, p)       
    x3 = (e*e - x1 - x2) % p    
    y3 = (e * (x1 - x3) - y1) % p
    ans = (x3, y3)
    return ans



def double_point(P, p, a):
    if P == 0:
        return P
    x1, y1 = P[0], P[1]
    e = frac_to_int(3 * x1 * x1 + a, 2 * y1, p)       
    x3 = (e * e - 2 * x1) % p     
    y3 = (e * (x1 - x3) - y1) % p
    Q = (x3, y3)
    return Q



def mult_point(P, k, p, a):
    s = bin(k)[2:]        
    Q = 0
    for i in s:
        Q = double_point(Q, p, a)
        if i == '1':
            Q = add_point(P, Q, p)
    return Q



def on_curve(args, P):
    p, a, b, h, G, n = args
    x, y = P
    if pow(y, 2, p) == ((pow(x, 3, p) + a*x + b) % p):
        return True
    return False



def encry_sm2(args, PB, M):
    p, a, b, h, G, n = args  
    M_bytes = bytes(M, encoding='ascii')
    k = random.randint(1, n-1)
    k_hex = hex(k)[2:] 
    C1 = mult_point(G, k, p, a)
    C1_bits = point_to_bits(C1)
    S = mult_point(PB, h, p, a)
    if S == 0:
        raise Exception("计算得到的S是无穷远点")
    x2, y2 = mult_point(PB, k, p, a)
    x2_bits = fielde_to_bits(x2)
    y2_bits = fielde_to_bits(y2)
    M_hex = bytes_to_hex(M_bytes)
    klen = 4 * len(M_hex)
    t = KDF(x2_bits + y2_bits, klen)
    if eval('0b' + t) == 0:
        raise Exception("KDF返回了全零串，请检查KDF算法！")
    t_hex = bits_to_hex(t)
    C2 = eval('0x' + M_hex + '^' + '0b' + t)
    x2_bytes = bits_to_bytes(x2_bits)
    y2_bytes = bits_to_bytes(y2_bits)
    hash_list = [i for i in x2_bytes + M_bytes + y2_bytes]
    C3 = sm3.sm3_hash(hash_list)
    C1_hex = bits_to_hex(C1_bits)
    C2_hex = hex(C2)[2:]
    C3_hex = C3
    C_hex = C1_hex + C2_hex + C3_hex
    print("加密得到的密文是：", C_hex)
    return C_hex


def decry_sm2(args, dB, C):
    p, a, b, h, G, n = args
    l = ceil(log(p, 2)/8)        
    bytes_l1 = 2*l+1
    hex_l1 = bytes_l1 * 2        
    C_bytes = hex_to_bytes(C)
    C1_bytes = C_bytes[0:2*l+1]
    C1 = bytes_to_point(C1_bytes)
    if not on_curve(args, C1):         
        raise Exception("在解密算法中，取得的C1不在椭圆曲线上！")
    x1, y1 = C1[0], C1[1]
    x1_hex, y1_hex = fielde_to_hex(x1), fielde_to_hex(y1)
    S = mult_point(C1, h, p, a)
    print("计算得到的S是：", S)
    if S == 0:
        raise Exception("在解密算法中，S是无穷远点！")
    xS, yS = S[0], S[1]
    xS_hex, yS_hex = fielde_to_hex(xS), fielde_to_hex(yS)
    temp = mult_point(C1, dB, p, a)
    x2, y2 = temp[0], temp[1]
    x2_hex, y2_hex = fielde_to_hex(x2), fielde_to_hex(y2)
    hex_l3 = 64          
    hex_l2 = len(C) - hex_l1 - hex_l3      
    klen = hex_l2 * 4 
    x2_bits, y2_bits = hex_to_bits(x2_hex), hex_to_bits(y2_hex)
    t = KDF(x2_bits + y2_bits, klen)
    if eval('0b' + t) == 0:
        raise Exception("在解密算法中，得到的t是全0串！")
    t_hex = bits_to_hex(t)
    C2_hex = C[hex_l1: -hex_l3]
    M1 = eval('0x' + C2_hex + '^' + '0x' + t_hex)   
    M1_hex = hex(M1)[2:].rjust(hex_l2, '0')   
    M1_bits = hex_to_bits(M1_hex)
    cmp_bits = x2_bits + M1_bits + y2_bits   
    cmp_bytes = bits_to_bytes(cmp_bits)
    cmp_list = [i for i in cmp_bytes]
    u = sm3.sm3_hash(cmp_list)      
    C3_hex = C[-hex_l3:]
    if u != C3_hex:
        raise Exception("在解密算法中，计算的u与C3不同！")
    M_bytes = hex_to_bytes(M1_hex)
    M = str(M_bytes, encoding='ascii')
    print("解密出的明文是：", M)
    return M



def get_args():
    p = eval('0x' + '8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3'.replace(' ', ''))
    a = eval('0x' + '787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498'.replace(' ', ''))
    b = eval('0x' + '63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A'.replace(' ', ''))
    h = 1
    xG = eval('0x' + '421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D'.replace(' ', ''))
    yG = eval('0x' + '0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2'.replace(' ', ''))
    G = (xG, yG)         
    n = eval('0x' + '8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7'.replace(' ', ''))
    args = (p, a, b, h, G, n)         
    return args



def get_key():
    xB = eval('0x' + '435B39CC A8F3B508 C1488AFC 67BE491A 0F7BA07E 581A0E48 49A5CF70 628A7E0A'.replace(' ', ''))
    yB = eval('0x' + '75DDBA78 F15FEECB 4C7895E2 C1CDF5FE 01DEBB2C DBADF453 99CCF77B BA076A42'.replace(' ', ''))
    PB = (xB, yB)     
    dB = eval('0x' + '1649AB77 A00637BD 5E2EFE28 3FBF3535 34AA7F7C B89463F2 08DDBC29 20BB0DA0'.replace(' ', ''))

    key_B = (PB, dB)
    return key_B



args = get_args()        
p, a, b, h, G, n = args     
p, a, b, h, xG, yG, n = tuple(map(lambda a: hex(a)[2:], (p, a, b, h, G[0], G[1], n)))  

key_B = get_key()   
PB, dB = key_B         
xB, yB, dB = tuple(map(lambda a: hex(a)[2:], (PB[0], PB[1], dB)))
M = input('请输入要加密的明文(明文应为ascii字符组成的字符串)：')
C = encry_sm2(args, key_B[0], M)            

de_M = decry_sm2(args, key_B[1], C)           

print("原始明文是：", M)
print("解密得到的明文是：", de_M)
if M == de_M:
    print("恭喜您，解密成功！")
else:
    print("解密失败，请检查算法！")
