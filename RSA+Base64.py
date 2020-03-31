# -*- coding: utf-8 -*-
import os
import rsa
import base64

prefix_m = b'-----BEGIN RSA + BASE64 MESSAGE-----\n'
suffix_m = b'\n-----END RSA + BASE64 MESSAGE-----\n'
prefix_s = b'-----BEGIN Signature-----\n'
suffix_s = b'\n-----END Signature-----'
encryption_method = 'SHA-1'


def findpem():
    keylist = list()
    files = os.listdir("./PublicKey/")
    for filename in files:
        if filename.endswith(".pem"):
            path = "./PublicKey/" + filename
            name = filename.rstrip(".pem")
            keylist.append({
                'name': name,
                'path': path
            })
    return keylist


def check_self_pem():  # 检查并生成
    exist_pri = os.path.exists('private.pem')
    exist_pub = os.path.exists('public.pem')
    if not exist_pri:
        print('未找到私钥')
    if not exist_pub:
        print('未找到公钥')
    if not exist_pri and not exist_pri:
        if input("是否生成新的密钥对(Y/N) >>>").lower() == "y":
            import generatekeys
        else:
            e = '无法找到密钥对'
            raise Exception(e)


check_self_pem()  # 先判断是否有公钥
PublicKeyList = findpem()

with open('private.pem', "rb") as privatefile:  # 加载自己的密钥
    p = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(p)


while True:
    Mode = int(input("选择模式：[0] 解密, [1] 加密) >>>"))
    if Mode:
        for index in range(len(PublicKeyList)):
            print('[{index}] {name}'.format(
                index=index, name=PublicKeyList[index]['name']))
        index = int(input("请选择收信人 >>>"))
        with open(PublicKeyList[index]['path'], "rb") as thirdfile:  # 加载 别人的公钥
            p = thirdfile.read()
            third = rsa.PublicKey.load_pkcs1(p)
        message = input('Message >>>')
        ciphertext = prefix_m + \
            base64.b64encode(rsa.encrypt(
                message.encode('utf-8'), third)) + suffix_m
        if input("是否签名(Y/N) >>>").lower() == "y":
            signature = base64.b64encode(
                rsa.sign(message.encode('utf-8'), privkey, encryption_method))
            ciphertext = ciphertext + prefix_s + signature + suffix_s
        with open('result.rsa', 'wb') as resultfile:
            resultfile.write(ciphertext)
        print('已将密文输出至 result.rsa')
    else:
        for index in range(len(PublicKeyList)):
            print('[{index}] {name}'.format(
                index=index, name=PublicKeyList[index]['name']))
        index = int(input("请选择发件人>>>"))
        with open(PublicKeyList[index]['path'], "rb") as thirdfile:  # 加载 别人的公钥
            p = thirdfile.read()
            third = rsa.PublicKey.load_pkcs1(p)
        with open('result.rsa', 'r') as resultfile:
            c = resultfile.read().split('\n')  # 按换行符分割
        crypto = base64.b64decode(c[1])  # 主体部分
        try:
            message = rsa.decrypt(crypto, privkey)
        except rsa.pkcs1.DecryptionError:
            print("无法解密，这可能不是给你的密文")
            input("回车重新开始")
            os.system('cls')
            continue
        else:
            message = message.decode('utf-8')
        if len(c) >= 5:
            signature = base64.b64decode(c[4])  # 签名部分sign 用私钥签名认证、再用公钥验证签名
            try:
                method_name = rsa.verify(
                    message.encode('utf-8'), signature, third)
            except rsa.pkcs1.VerificationError:
                print("× 签名无效")
            else:
                if method_name == encryption_method:
                    print('√ 签名有效 [%s]' % method_name)
            finally:
                print("信息为："+ message)
        else:
            print('× 没有签名')
            print("信息为："+ message)
    
    input("回车重新开始")
    os.system('cls')
