from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import win32



# ------------------------------------BASIC Encrypt Part---------------------------------- #
def pkcs7padding(_data: bytes, _block_size: int) -> bytes:
    padding_size = _block_size - len(_data) % _block_size
    return _data + chr(padding_size).encode() * padding_size

def pkcs7unpadding(_data: bytes) -> bytes: # 去填充
    length = len(_data)
    return _data[0:length - int(_data[-1])]

def aes_encrypt(_key: bytes, _data: bytes) -> bytes:
    cipher = AES.new(_key, AES.MODE_CBC, _key[0:16])
    return cipher.encrypt(pkcs7padding(_data, AES.block_size))

def aes_decrypt(_key: bytes, _data: bytes) -> bytes:
    cipher = AES.new(_key, AES.MODE_CBC, _key[0:16])
    return pkcs7unpadding(cipher.decrypt(_data), AES.block_size)

def gen_rsakey(_length: int, _passphrase: int) -> bytes *2:
    key = RSA.generate(_length)
    return key.export_key(passphrase=_passphrase), key.publickey().export_key()

def rsa_decrypt(_pubkey, _prikey, _data: bytes, _session_key: bytes) -> bytes:
    cipher_rsa = PKCS1_OAEP.new(_prikey)
    _session_key = cipher_rsa.decrypt(_session_key)
    return aes_decrypt(_session_key, _data)

def rsa_encrypt(_pubkey, _prikey, _data: bytes) -> bytes *2:
    _session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(_pubkey)
    return cipher_rsa.encrypt(_session_key), aes_encrypt(_session_key, _data)
    
def pss_sign(_prikey, _data: bytes) -> bytes:
    _hash = SHA256.new(_data)
    return pss.new(_prikey).sign(_hash)

def pss_verify(_pubkey, _data: bytes, _signature: bytes) -> bool:
    verifier = pss.new(_pubkey)
    _hash = SHA256.new(_data)
    try: verifier.verify(_hash, _signature); return True
    except Exception as E: return False

# 

def set_text(text):
    win32.win32clipboard.OpenClipboard()
    win32.win32clipboard.EmptyClipboard()
    win32.win32clipboard.SetClipboardData(win32.lib.win32con.CF_OEMTEXT, text)
    win32.win32clipboard.CloseClipboard()

if __name__ == "__main__":
    recipient_key = RSA.import_key(open("receiver.pem").read())
    private_key = RSA.import_key(open("private.pem").read())
    massage = b'test'
    
