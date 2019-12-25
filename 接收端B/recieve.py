#!/usr/bin/env python3
#coding:utf-8
#by spwpun

def main():
    f = open('r_message.txt','r')
    messages = f.readlines()
    f.close()
    #读取自己私钥信息
    f1 = open('B_D.txt','r')
    bd = int(f1.read(),16)
    f1.close()
    f2 = open('B_N.txt','r')
    bn = int(f2.read(),16)
    f2.close()
    #读取A的公钥进行签名验证
    f = open('A_E.txt','r')
    ae = int(f.read(),16)
    f.close()
    f = open('A_N.txt','r')
    an = int(f.read(),16)
    f.close()

    hM,cipher,auth,sessionkey = messages[0][0:-1],messages[1][0:-1],messages[2][0:-1],messages[3]#去掉最后的换行符号
    key = rsa_decrypt(sessionkey,bd,bn)
    hex_key = a2hex(key)
    info = ECB_decrypt(cipher,hex_key)
    info = hex2a(info)
    hm = Sha_1(info)
    Hm = rsa_decrypt(auth,ae,an)      #进行签名验证
    print("用私钥解密得到会话密钥：",key)
    print("用会话密钥解密密文的到明文：",info)
    #通过比较认证码来进行消息认证和身份鉴别
    if Hm == hM and hm == hM:
        print("验证成功！")
    else:
        print("验证失败！")




#SHA-1算法
#先写4个基本逻辑函数,返回的是数字
def f1(A,B,C):	#传入的是3个8位16进制字符串
	tmp = (int(A,16)&int(B,16))|((~int(A,16))&int(C,16))
	return tmp%(2**32)

def f2(A,B,C):
	tmp = (int(A,16)^int(B,16)^int(C,16))
	return tmp

def f3(A,B,C):
	tmp = (int(A,16)&int(B,16))|(int(A,16)&int(C,16))|(int(B,16)&int(C,16))
	return tmp

def f4(A,B,C):
	return f2(A,B,C)

#循环左移n位,传入一个数，n为左移的位数,返回结果的16进制字符串
def loopmove(num,n):
	tmp = (num<<n)|(num>>32-n)
	return hex(tmp%(2**32))[2:]

#得到明文信息的已分组填充好的二进制字符串，返回一个列表，列表元素是一个512位二进制字符串
def getBinstr(rawstr):
	binstr = ""
	for ch in rawstr:
		c = bin(ord(ch))[2:]
		if len(c)!=8:
			c = "0"*(8-len(c))+c
		binstr += c
	binstr += "1"	#加界定符1
	while(len(binstr)%512!=448):
		binstr +="0"#补位至模512余448，后面再添加64位长度值
	ext = bin(len(rawstr)*8)[2:]	#字符串的长度
	if len(ext)<64:
		ext = "0"*(64-len(ext))+ext	#附加长度值
	binstr = binstr+ext
	#以512位分组
	messages = []
	for i in range(0,len(binstr),512):
		messages.append(binstr[i:i+512])
	return messages

#压缩操作中的循环函数
def compress(A,B,C,D,E,W,K,time):
	for t in range(time*20,time*20+20):
		a,b,c,d,e = A,B,C,D,E
		if t>=0 and t<20:
			var1 = (int(E,16)+f1(B,C,D))%(2**32)
		elif t<40:
			var1 = (int(E,16)+f2(B,C,D))%(2**32)
		elif t<60:
			var1 = (int(E,16)+f3(B,C,D))%(2**32)
		elif t<80:
			var1 = (int(E,16)+f4(B,C,D))%(2**32)
		var2 = (int(loopmove(int(A,16),5),16)+int(W[t],16))%(2**32)
		var3 = (var1+var2)%(2**32)
		A = hex((var3+int(K[time],16))%(2**32))[2:]
		B = a
		C = loopmove(int(b,16),30)
		D = c
		E = d
	return A,B,C,D,E

def Sha_1(rawstr):
	H = ["67452301","EFCDAB89","98BADCFE","10325476","C3D2E1F0"]	#五个寄存器常量，K的初始化
	K = ["5A827999","6ED9EBA1","8F1BBCDC","CA62C1D6"]
	messages = getBinstr(rawstr)
	A,B,C,D,E = H[0],H[1],H[2],H[3],H[4]
	for binstr in messages:
		a,b,c,d,e = A,B,C,D,E
		W = []
		for i in range(0,512,32):
			intstr = int(binstr[i:i+32],2)
			W.append(hex(intstr)[2:])	#产生前16个32位字
		for t in range(16,80):
			wt = (int(W[t-16],16)^int(W[t-14],16)^int(W[t-8],16)^int(W[t-3],16))
			wt = loopmove(wt,1)
			W.append(wt)	#80个32位字已存入W列表
		# print(W)
		#80个步骤，4次循环
		A,B,C,D,E = compress(A,B,C,D,E,W,K,0)
		A,B,C,D,E = compress(A,B,C,D,E,W,K,1)
		A,B,C,D,E = compress(A,B,C,D,E,W,K,2)
		A,B,C,D,E = compress(A,B,C,D,E,W,K,3)
		#最后把A,B,C,D,E寄存器的值与初始值相加模32位
		A = hex((int(a,16)+int(A,16))%(2**32))[2:]
		B = hex((int(b,16)+int(B,16))%(2**32))[2:]
		C = hex((int(c,16)+int(C,16))%(2**32))[2:]
		D = hex((int(d,16)+int(D,16))%(2**32))[2:]
		E = hex((int(e,16)+int(E,16))%(2**32))[2:]
	res = A+B+C+D+E
	if len(res)<40:
		res = '0'*(40-len(res))+res
	print("消息的认证码：",res)
	return res

#*----DES_ECB加密算法----*
#初始置换IP表
ip = [57,49,41,33,25,17, 9,1,
      59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,
      63,55,47,39,31,23,15,7,
      56,48,40,32,24,16, 8,0,
      58,50,42,34,26,18,10,2,
      60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6]

#初始逆置换_IP表
_ip = [39,7,47,15,55,23,63,31,
       38,6,46,14,54,22,62,30,
       37,5,45,13,53,21,61,29,
       36,4,44,12,52,20,60,28,
       35,3,43,11,51,19,59,27,
       34,2,42,10,50,18,58,26,
       33,1,41, 9,49,17,57,25,
       32,0,40, 8,48,16,56,24]

#E-扩展运算表
E_table = [31, 0, 1, 2, 3, 4,
           3 , 4, 5, 6, 7, 8,
           7 , 8, 9,10,11,12,
           11,12,13,14,15,16,
           15,16,17,18,19,20,
           19,20,21,22,23,24,
           23,24,25,26,27,28,
           27,28,29,30,31, 0]

#S-盒
S_table = [[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
            [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
            [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
            [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],#S1
           [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
            [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
            [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
            [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],#S2
           [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
            [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
            [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
            [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],#S3
           [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
            [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
            [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
            [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],#S4
           [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
            [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
            [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
            [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],#S5
           [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
            [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
            [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
            [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],#S6
           [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
            [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
            [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
            [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],#S7
           [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
            [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
            [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
            [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]]#S8

#P-置换表
P_table = [15, 6,19,20,28,11,27,16,
            0,14,22,25, 4,17,30, 9,
            1, 7,23,13,31,26, 2, 8,
           18,12,29, 5,21,10, 3,24]

#置换选择表PC-1
PC_1 = [56,48,40,32,24,16, 8,
         0,57,49,41,33,25,17,
         9, 1,58,50,42,34,26,
        18,10, 2,59,51,43,35,
        62,54,46,38,30,22,14,
         6,61,53,45,37,29,21,
        13, 5,60,52,44,36,28,
        20,12, 4,27,19,11, 3]

#置换选择表PC-2
PC_2 = [13,16,10,23, 0, 4, 2,27,
        14, 5,20, 9,22,18,11, 3,
        25, 7,15, 6,26,19,12, 1,
        40,51,30,36,46,54,29,39,
        50,44,32,47,43,48,38,55,
        33,52,45,41,49,35,28,31]

#LS(i)的取值
LS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]


#十六进制转换为二进制
def HexToBin(hex):
    msg = ""
    for char in hex:
        temp = bin(int(char, 16))[2:]
        if len(temp) < 4:
            msg += '0' * (4-len(temp))
        msg += temp
    return msg

#二进制转换为十六进制
def BinToHex(bin):
    msg = ""
    i = 0
    while(i < len(bin)):
        msg += hex(int(bin[i:i+4], 2))[2:]
        i += 4
    return msg

#异或运算
def xor(str1, str2, n):
    str = ""
    for i in range(n):
        if str1[i] != str2[i]:
            str += '1'
        else:
            str += '0'
    return str


#子密钥生成器,key_hex为初始密钥(16进制)
def createKey(key_hex):
    key_bin = HexToBin(key_hex)
    PC_1_K = ""
    key_list = []

    #PC-1置换
    for i in range(56):
        PC_1_K += key_bin[PC_1[i]]

    C = PC_1_K[0:28]
    D = PC_1_K[28:56]

    for i in range(0, 16):
        key_i = ""

        #LS(i)左循环移位
        C = C[LS[i]:] + C[:LS[i]]
        D = D[LS[i]:] + D[:LS[i]]

        #PC-2置换
        PC_2_K = C + D
        for j in range(48):
            key_i += PC_2_K[PC_2[j]]

        key_list.append(key_i)

    return key_list


#DES加密函数
def des_encrypt(msg_hex, key_hex):
    msg_bin = HexToBin(msg_hex)

    #子密玥生成器生成子密玥列表
    key_list = createKey(key_hex)

    #IP置换
    ip_k = ""
    for i in range(64):
        ip_k += msg_bin[ip[i]]
    L = ip_k[0: 32]
    R = ip_k[32: 64]

    for i in range(16):

        key_i = key_list[i]

        #E-扩展运算
        E_R = ""
        for j in range(48):
            E_R += R[E_table[j]]

        #密钥与E(R)异或
        K_E_R = xor(key_i, E_R, 48)

        #S-盒运算
        S = ""
        n = 0
        for j in range(8):
            temp = K_E_R[n : n+6]
            s_i= hex(S_table[j][int(temp[0]+temp[5],2)][int(temp[1:5],2)])[2:]
            S += s_i
            n += 6
        S_bin = HexToBin(S)

        #P-置换运算
        P = ""
        for j in range(32):
            P += S_bin[P_table[j]]

        #L与 R异或，L和 R互换
        temp = xor(L, P, 32)
        L = R
        R = temp

    #位置交换
    L, R = R, L

    #初始逆置换
    ciper = ""
    _ip_k = L + R
    for i in range(64):
        ciper += _ip_k[_ip[i]]

    return BinToHex(ciper)


#DES解密函数
def des_decrypt(cpr_hex, key_hex):
    cpr_bin = HexToBin(cpr_hex)

    # 子密玥生成器生成子密玥列表
    key_list = createKey(key_hex)

    # IP置换
    ip_k = ""
    for i in range(64):
        ip_k += cpr_bin[ip[i]]
    L = ip_k[0: 32]
    R = ip_k[32: 64]

    for i in range(16):

        key_i = key_list[15-i]

        # E-扩展运算
        E_R = ""
        for j in range(48):
            E_R += R[E_table[j]]

        # 密钥与E(R)异或
        K_E_R = xor(key_i, E_R, 48)

        # S-盒运算
        S = ""
        n = 0
        for j in range(8):
            temp = K_E_R[n: n + 6]
            s_i = hex(S_table[j][int(temp[0] + temp[5], 2)][int(temp[1:5], 2)])[2:]
            S += s_i
            n += 6
        S_bin = HexToBin(S)

        # P-置换运算
        P = ""
        for j in range(32):
            P += S_bin[P_table[j]]

        # L与 R异或，L和 R互换
        temp = xor(L, P, 32)
        L = R
        R = temp

    # 位置交换
    L, R = R, L

    # 初始逆置换
    msg = ""
    _ip_k = L + R
    for i in range(64):
        msg += _ip_k[_ip[i]]

    return BinToHex(msg)


#读取文件信息
def readMessage(filename):
    msg = ""
    with open(filename) as f:
        try:
            for line in f.readlines():
                msg += line
        finally:
            f.close()
    return msg

#写入文件信息
def writeMessage(filename, msg):
    try:
        f = open(filename, 'a')
        f.write(msg + '\n')
    finally:
        f.close()


#ECB加密模式
def ECB_encrypt(msg, key):
    ciper = ""

    while(len(msg) >= 16):
        ciper += des_encrypt(msg[0:16], key)
        msg = msg[16:]

    if len(msg) != 0:
        msg += (16-len(msg)) * '0'
        ciper += des_encrypt(msg, key)

    return ciper

#ECB解密模式
def ECB_decrypt(cpr, key):
    msg = ""
    while(len(cpr) > 0):
        msg += des_decrypt(cpr[0:16], key)
        cpr = cpr[16:]

    return msg


#-----*****RSA算法*****-----
#平方—乘法，最后返回结果
def MRF(b,n,m):
    
        a=1
        x=b;y=n;z=m
        binstr = bin(n)[2:][::-1]	#通过切片去掉开头的0b，截取后面，然后反转
        for item in binstr:
                if item == '1':
                        a = (a*b)%m
                        b = (b**2)%m
                elif item == '0':
                        b = (b**2)%m
        return a
                                
#加密，传入公钥，通过读取明文文件进行加密
def rsa_encrypt(m,e,n):
        cipher = ""
        nlength = len(str(hex(n))[2:])  #计算n的16进制长度，以便分组
        message = m             #读取明文
        for i in range(0,len(message),8):
            if i==len(message)//8*8:
                m = int(a2hex(message[i:]),16)  #最后一个分组
            m = int(a2hex(message[i:i+8]),16)
            c = MRF(m,e,n)
            cipher1 = str(hex(c))[2:]
            if len(cipher1)!=nlength:
                cipher1 = '0'*(nlength-len(cipher1))+cipher1    #每一个密文分组，长度不够，高位补0
            cipher += cipher1
        return cipher
#解密,传入私钥，通过文件读写进行解密
def rsa_decrypt(c,d,n):
        #加密之后每一个分组的长度和n的长度相同
        cipher = c
        message = ""
        nlength = len(str(hex(n))[2:])
        for i in range(0,len(cipher),nlength):
            c = int(cipher[i:i+nlength],16)     #得到一组密文的c
            m = MRF(c,d,n)
            info = hex2a(str(hex(m))[2:])
            message += info
        return message

#求最大公因子
def gcd(a,b):  
        if a%b == 0:
                return b
        else :
                return gcd(b,a%b)

#求逆元
def Ex_Euclid(x,n):
    r0=n
    r1=x%n
    if r1==1:
        y=1
    else:
        s0=1
        s1=0
        t0=0
        t1=1
        while (r0%r1!=0):
            q=r0//r1  
            r=r0%r1  
            r0=r1  
            r1=r  
            s=s0-q*s1 
            s0=s1 
            s1=s  
            t=t0-q*t1  
            t0=t1  
            t1=t  
            if r==1:
                y = (t+n)%n
    return y

#ascii_to_hex
def a2hex(raw_str):
        hex_str = ''
        for ch in raw_str:
                hex_str += hex(ord(ch))[2:]
        return hex_str

#hex_to_ascii
def hex2a(raw_str):
        asc_str = ''
        for i in range(0,len(raw_str),2):
            if int(raw_str[i:i+2],16)==0:   #如果16进制为0,默认不转换为NULL
                pass
            else:
                asc_str += chr(int(raw_str[i:i+2],16))
        return asc_str

if __name__ == "__main__":
        main()
