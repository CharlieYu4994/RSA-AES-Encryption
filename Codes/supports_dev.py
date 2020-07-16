from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import sqlite3



# ------------------------------------BASIC Encrypt Part---------------------------------- #
def pkcs7padding(_data: bytes, _block_size: int) -> bytes:
    _padding_size = _block_size - len(_data) % _block_size
    return _data + chr(_padding_size).encode() * _padding_size


def pkcs7unpadding(_data: bytes) -> bytes:  # 去填充
    _length = len(_data)
    return _data[0:_length - int(_data[-1])]


def aes_encrypt(_key: bytes, _data: bytes) -> bytes:
    _cipher = AES.new(_key, AES.MODE_CBC, _key[0:16])
    return _cipher.encrypt(pkcs7padding(_data, AES.block_size))


def aes_decrypt(_key: bytes, _data: bytes) -> bytes:
    _cipher = AES.new(_key, AES.MODE_CBC, _key[0:16])
    return pkcs7unpadding(_cipher.decrypt(_data), AES.block_size)


def gen_rsakey(_length: int, _passphrase: str) -> bytes:
    _key = RSA.generate(_length)
    return _key.export_key(passphrase=_passphrase if _passphrase else None),\
           _key.publickey().export_key()


def rsa_decrypt(_pubkey, _prikey, _data: bytes, _session_key: bytes) -> bytes:
    _cipher = PKCS1_OAEP.new(_prikey)
    _session_key = _cipher.decrypt(_session_key)
    return aes_decrypt(_session_key, _data)


def rsa_encrypt(_pubkey, _prikey, _data: bytes) -> bytes:
    _session_key = get_random_bytes(16)
    _cipher = PKCS1_OAEP.new(_pubkey)
    return _cipher.encrypt(_session_key), aes_encrypt(_session_key, _data)


def pss_sign(_prikey, _data: bytes) -> bytes:
    _hash = SHA256.new(_data)
    return pss.new(_prikey).sign(_hash)


def pss_verify(_pubkey, _data: bytes, _signature: bytes) -> bool:
    _verifier = pss.new(_pubkey)
    _hash = SHA256.new(_data)
    try:
        _verifier.verify(_hash, _signature)
        return True
    except Exception as E:
        return False

# ---------------------------------------Database Part------------------------------------ #


def gen_database():
    _db = sqlite3.connect('keys.db')
    _cursor = _db.cursor()
    _cursor.execute('''CREATE TABLE UserKeys(
				ID           INTEGER PRIMARY KEY,
				PubKey       TEXT    NOT NULL,
				PriKey       TEXT    NOT NULL,
				Describe     CHAR(30)         );''')
    _cursor.execute('''CREATE TABLE ThirdKeys(
				ID           INTEGER PRIMARY KEY,
				PubKey       TEXT    NOT NULL,
				Name         CHAR(10)NOT NULL );''')
    _db.commit()
    _db.close()

def add_userkey(_pubkey: bytes, _prikey: bytes, _describe: str, _db):
    _cursor = _db.cursor()
    _cursor.execute(f"INSERT INTO UserKeys (PubKey, PriKey, describe) \
			      VALUES ('{_pubkey.decode()}', '{_prikey.decode()}', '{_describe}')")
    _db.commit()

def del_key(_id: int, _table: str, _db):
    _cursor = _db.cursor()
    _cursor.execute(f"DELETE FROM '{_table}' WHERE id = {_id}")
    _db.commit()
 

if __name__ == "__main__":
    # gen_database()
    database = sqlite3.connect('keys.db')
    #prikey, _pubkey = gen_rsakey(3072, '')
    #add_userkey(_pubkey, prikey, '测试', database)
    del_key(1, 'UserKeys', database)
