import rsa

# 先生成一对密钥，然后保存.pem格式文件，当然也可以直接使用
pubkey, privkey = rsa.newkeys(2048)

pub = pubkey.save_pkcs1()
pubfile = open('public.pem', 'wb')
pubfile.write(pub)
pubfile.close()

pri = privkey.save_pkcs1()
prifile = open('private.pem', 'wb')
prifile.write(pri)
prifile.close()

prifile = open('third.pem', 'wb')
prifile.write(b'')
prifile.close()
