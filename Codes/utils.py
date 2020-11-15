from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from typing import Tuple, Union, Generator, Dict, Optional, List
import sqlite3, os, base64, re, binascii
from sqlite3 import Connection

standard_return = Tuple[bool, int, Union[str, int, float]]
standard_keyrtn = Tuple[bool, Union[RsaKey, bytes], Union[RsaKey, bytes]]

msg_prefix = '-----BEGIN MESSAGE-----\n'
msg_suffix = '\n-----END MESSAGE-----'


# ------------------------------------BASIC Encrypt Part---------------------------------- #
def pkcs7padding(_data: bytes, _block_size: int) -> bytes:
    _padding_size = _block_size - len(_data) % _block_size
    return _data + chr(_padding_size).encode() * _padding_size

def pkcs7unpadding(_data: bytes) -> bytes:
    _length = len(_data)
    return _data[0:_length - int(_data[-1])] 

def aes_encrypt(_key: bytes, _data: bytes, _pad=True) -> bytes:
    _cipher = AES.new(_key, AES.MODE_CBC, _key[0:16])
    return _cipher.encrypt(pkcs7padding(_data, AES.block_size) if _pad else _data)

def aes_decrypt(_key: bytes, _data: bytes, _pad=True) -> bytes:
    _cipher = AES.new(_key, AES.MODE_CBC, _key[0:16])
    return pkcs7unpadding(_cipher.decrypt(_data)) if _pad else _cipher.decrypt(_data)

def rsa_encrypt(_pubkey: RsaKey, _data: bytes) -> bytes:
    _cipher = PKCS1_OAEP.new(_pubkey)
    return _cipher.encrypt(_data)

def rsa_decrypt(_prikey: RsaKey, _data: bytes) -> bytes:
    _cipher = PKCS1_OAEP.new(_prikey)
    return _cipher.decrypt(_data)

def composite_encrypt(_pubkey: RsaKey, _data: bytes) -> Tuple[bytes, bytes]:
    _session_key = get_random_bytes(16)
    return rsa_encrypt(_pubkey, _session_key), aes_encrypt(_session_key, _data)

def composite_decrypt(_prikey: RsaKey, _data: bytes, _session_key: bytes) -> bytes:
    _session_key = rsa_decrypt(_prikey, _session_key)
    return aes_decrypt(_session_key, _data)

def pss_sign(_prikey: RsaKey, _data: Union[bytes, None], _hash=None) -> bytes:
    _hash = _hash if _hash else SHA256.new(_data)
    return pss.new(_prikey).sign(_hash)

def pss_verify(_pubkey: RsaKey, _data: Union[bytes, None], _signature: bytes, _hash=None) -> bool:
    _verifier = pss.new(_pubkey)
    _hash = _hash if _hash else SHA256.new(_data)
    try:
        _verifier.verify(_hash, _signature)
        return True
    except Exception as E:
        return False

def gen_rsakey(_length: int, _passphrase: str) -> standard_keyrtn:
    _key = RSA.generate(_length)
    return True, _key.export_key(passphrase=_passphrase if _passphrase else None),\
           _key.publickey().export_key()

def load_key(_pubkey: bytes, _prikey: Union[bytes, None] = None, _passphrase: Optional[str] = '') -> standard_keyrtn:
    if _prikey:
        try:
            _pubkey_r = RSA.import_key(_pubkey)
            _prikey_r = RSA.import_key(_prikey, passphrase=_passphrase if _passphrase else None)
        except Exception as E: return False, str(E).encode(), b''
        else: return True, _prikey_r, _pubkey_r
    else: return True, RSA.import_key(_pubkey), b''

def expert_key(_prikey, _passphrase: str) -> bytes:
    return _prikey.export_key(passphrase=_passphrase if _passphrase else None)

# ---------------------------------------Database Part------------------------------------ #
def gen_database():
    if not os.path.exists('keyring.db'):
        _db = sqlite3.connect('keyring.db')
        _cursor = _db.cursor()
        _cursor.execute("""CREATE TABLE UserKeys(
                    ID           INTEGER PRIMARY KEY,
                    PubKey       TEXT    NOT NULL,
                    PriKey       TEXT    NOT NULL,
                    Describe     CHAR(50)         );""")
        _cursor.execute("""CREATE TABLE ThirdKeys(
                    ID           INTEGER PRIMARY KEY,
                    PubKey       TEXT    NOT NULL,
                    Describe     CHAR(20)NOT NULL );""")
        _cursor.execute("""CREATE TABLE Resources(
                    ID           INTEGER PRIMARY KEY,
                    Field        CHAR(15)NOT NULL UNIQUE,
                    Value        TEXT    NOT NULL);""")
        gen_cfg(_db)
        _db.commit()
        _db.close()

def add_userkey(_prikey: bytes, _pubkey: bytes, _describe: str, _db: Connection):
    _cursor = _db.cursor()
    _cursor.execute(f"INSERT INTO UserKeys (PubKey, PriKey, Describe) \
			          VALUES ('{_pubkey.decode()}', '{_prikey.decode()}', '{_describe}')")
    _db.commit()

def add_thirdkey(_pubkey: bytes, _describe: str, _db: Connection):
    _cursor = _db.cursor()
    _cursor.execute(f"INSERT INTO ThirdKeys (PubKey, Describe) \
			          VALUES ('{_pubkey.decode()}', '{_describe}')")
    _db.commit()

def del_key(_id: int, _table: str, _db: Connection):
    _cursor = _db.cursor()
    _cursor.execute(f"DELETE FROM {_table} WHERE ID='{_id}'")
    _db.commit()

def alt_key(_id: int, _field: str, _value: str, _table: str, _db: Connection):
    _cursor = _db.cursor()
    _cursor.execute(f"UPDATE {_table} SET '{_field}'='{_value}' WHERE ID='{_id}'")
    _db.commit()

def get_keydict(_table: str, _db: Connection) -> Dict[str, int]:
    _keydict = dict()
    _cursor = _db.cursor()
    for row in _cursor.execute(f"SELECT ID, Describe FROM '{_table}'").fetchall():
        _keydict[f'{row[1]} ({str(row[0])})'] = row[0]
    return _keydict

def get_userkey(_id: int, _db: Connection) -> Tuple[bytes, bytes]:
    _cursor = _db.cursor()
    _pubkey, _prikey = _cursor.execute(f"SELECT PubKey, PriKey FROM UserKeys \
                                         WHERE ID='{_id}'").fetchall()[0]
    return _prikey.encode(), _pubkey.encode()

def get_thirdkey(_id: int, _db: Connection) -> bytes:
    _cursor = _db.cursor()
    _cursor.execute(f"SELECT PubKey FROM ThirdKeys WHERE ID='{_id}'")
    return _cursor.fetchall()[0][0].encode()

def add_res(_field: str, _value: str, _db: Connection):
    _cursor = _db.cursor()
    _cursor.execute(f"INSERT INTO Resources (Field, Value)\
                      VALUES ('{_field}', '{_value}')")
    _db.commit()

def del_res(_field: str, _db: Connection):
    _cursor = _db.cursor()
    _cursor.execute(f"DELETE FROM Resources WHERE Field='{_field}'")
    _db.commit()

def alt_res(_field: str, _value: str, _db: Connection):
    _cursor = _db.cursor()
    _cursor.execute(f"UPDATE Resources SET Value='{_value}' WHERE Field='{_field}'")
    _db.commit()

def get_res(_field: str, _db: Connection) -> str:
    _cursor = _db.cursor()
    _cursor.execute(f"SELECT Value FROM Resources WHERE Field='{_field}'")
    return _cursor.fetchall()[0][0]

# -----------------------------------------Other Part------------------------------------- #
def read_file(_path: str, _seek: int) -> Generator[Tuple[bytes, bool], None, None]:
    BLOCK_SIZE = 1048576
    with open(_path, 'rb') as f:
        if _seek: f.seek(_seek, 0)
        while True:
            block = f.read(BLOCK_SIZE)
            if block: yield block, len(block) != BLOCK_SIZE
            else: return

def get_cfg(_db):
    _siteroot = get_res('siteroot', _db)
    _outputpath = get_res('outputpath', _db)
    _defaultkey = get_res('defaultkey', _db)
    return _siteroot, _outputpath, _defaultkey

def gen_cfg(_db):
    add_res('siteroot', 'key.kagurazakaeri.com', _db)
    add_res('outputpath', '', _db)
    add_res('defaultkey', '', _db)

def alt_cfg(_siteroot: str, _outputdir: str, _defaultkey: str, _db):
    alt_res('siteroot', _siteroot, _db)
    alt_res('outputpath', _outputdir, _db)
    alt_res('defaultkey', _defaultkey, _db)

# -----------------------------------------High Level------------------------------------- #
class interface(object):
    @staticmethod
    def get_user_input(self, describe):
        raise(NotImplementedError)
    
    @staticmethod
    def warnmethod(self, msg, warn_type, title):
        raise(NotImplementedError)
    
    @staticmethod
    def show_result(self, msg, msg_type, sig):
        raise(NotImplementedError)

class keymanagement(object):
    thirdkeydict: Dict[str, int] = dict()
    userkeydict: Dict[str, int] = dict()
    thirdkeylist: List[str] = list()
    userkeylist: List[str] = list()

    def __init__(self, _database):
        self.database = _database
    
    def get_user_input(self, _describe):
        interface.get_user_input(self, _describe)
    
    def warnmethod(self, _msg, _warn_type, _title):
        interface.warnmethod(self, _msg, _warn_type, _title)
        
    def show_result(self, _msg, _msg_type, _sig):
        interface.show_result(self, _msg, _msg_type, _sig)

    def alt_pass(self, _id: int, _passphrase_o: str, _passphrase_n: str, _db: Connection) -> bool:
        _prikey_t, _pubkey_t = get_userkey(_id, _db)
        _status, _prikey, _ = load_key(_pubkey_t, _prikey_t, _passphrase_o)
        if not _status: return False
        alt_key(_id, 'PriKey', expert_key(_prikey, _passphrase_n).decode(), 'UserKeys', _db)
        return True

    def del_key(self, key_type: int):
        u_id = self.get_u_id(key_type)
        keylist = self.userkey_ls if key_type == 0 else self.thirdkey_ls
        del_key(u_id, 'UserKeys' if key_type == 0 else 'ThirdKeys', self.database)
        keylist.delete('active')

    def rename(self, key_type: int):
        u_id = self.get_u_id(key_type)
        keylist = self.userkey_ls if key_type == 0 else self.thirdkey_ls
        input_window = InputWindow('描述  :', True)
        self.wait_window(input_window)
        describe = input_window.result if input_window.result else keylist.get('active')[:-4]
        alt_key(u_id, 'Describe', describe, 'UserKeys' if key_type == 0 else 'ThirdKeys',
                         self.database)
        self.freshkeylist()

    def alt_pass(self):
        u_id = self.get_u_id(0)
        input_window = InputWindow('新密码:', False)
        self.wait_window(input_window)
        password_n = input_window.result
        for _ in range(5):
            input_window = InputWindow('旧密码:', False)
            self.wait_window(input_window)
            passwoed_o = input_window.result
            status = alt_pass(u_id, passwoed_o, password_n, self.database)
            if status: return
            else: tkinter.messagebox.showwarning('Warning', '密码错误')
        tkinter.messagebox.showwarning('Warning', '密码五次输入错误，请重试'); return


    def import_key(self, path: str):
        with open(path, 'rb') as file_in:
            temp = file_in.read(1048576).decode()
            prikey = re.search(r'-----BEGIN RSA[\s\S]*PRIVATE KEY-----', temp)
            pubkey = re.search(r'-----BEGIN PUBLIC[\s\S]*BLIC KEY-----', temp)
            input_window = InputWindow('描述  :', True)
            self.wait_window(input_window)
            if prikey and pubkey:
                add_userkey(prikey.group().encode(), pubkey.group().encode(),
                                     input_window.result, self.database)
            elif not prikey and pubkey:
                add_thirdkey(pubkey.group().encode(), input_window.result, self.database)
            else:
                tkinter.messagebox.showerror('Error', '密钥格式无效')
            self.freshkeylist()

    def export_key(self, key_type: int, path: str):
        with open(path, 'w') as file_out:
            u_id = self.get_u_id(key_type)
            if key_type == 0:
                _, pubkey = get_userkey(u_id, self.database)
                file_out.write(pubkey.decode())
            else:
                pubkey = get_thirdkey(u_id, self.database)
                file_out.write(pubkey.decode())

    def export_pri_key(self, path: str):
        with open(path, 'wb') as file_out:
            u_id = self.get_u_id(0)
            prikey, pubkey = get_userkey(u_id, self.database)
            file_out.write(prikey)
            file_out.write(pubkey)

    def get_u_id(self, key_type: int):
        keylist = self.userkey_ls if key_type == 0 else self.thirdkey_ls
        keydict = self.userkeydict if key_type == 0 else self.thirdkeydict
        return keydict[keylist.get('active')]

class basiclogic(object):
    thirdkeydict: Dict[str, int] = dict()
    userkeydict: Dict[str, int] = dict()
    thirdkeylist: List[str] = list()
    userkeylist: List[str] = list()
    cfg = prikey = pubkey = thirdkey = None

    def __init__(self, _database):
        self.database = _database
        self.getkeylist()
        self.cfg = get_cfg(self.database)
    
    def get_user_input(self, describe):
        interface.get_user_input(self, describe)
    
    def warnmethod(self, msg, warn_type, title):
        interface.warnmethod(self, msg, warn_type, title)
        
    def show_result(self, msg, msg_type, sig):
        interface.show_result(self, msg, msg_type, sig)
    
    def keymanagement(self):
        dialog = keymanagement(self.database)

    
    def getkeylist(self):
        self.userkeydict = get_keydict('UserKeys', self.database)
        self.thirdkeydict = get_keydict('ThirdKeys', self.database)
        self.userkeylist = list(self.userkeydict.keys())
        self.thirdkeylist = list(self.thirdkeydict.keys())
    
    def freshkeylist(self):
        self.getkeylist()

    def select_thirdkey(self, describe):
        u_id = self.thirdkeydict[describe]
        _, self.thirdkey, _ = load_key(get_thirdkey(u_id, self.database))

    def select_userkey(self, describe, extraoperate, args):
        u_id = self.userkeydict[describe]
        prikey_t, pubkey_t = get_userkey(u_id, self.database)

        for _ in range(5):
            passphase = self.get_user_input('密码: ')
            status, prikey, pubkey = load_key(pubkey_t, prikey_t, describe)
            if not status: self.warnmethod('密码错误', 1, 'Warning'); continue
            self.prikey, self.pubkey = prikey, pubkey; break

        if not status:
            self.warnmethod('密码五次输入错误，请重新选择', 1, 'Warning')
            extraoperate(*args)

    def save_cfg(self, url, outputdir, defaultkey):
        alt_cfg(url, outputdir, defaultkey, self.database)

    def gen_key(self):
        _, prikey, pubkey = gen_rsakey(2048, self.get_user_input('密码: '))
        describe = self.get_user_input('描述: ')
        describe = describe if describe else 'UserKey'
        add_userkey(prikey, pubkey, describe, self.database)
        self.freshkeylist()

    def encrypt_text(self, message, sign_check=True):
        final_message = encrypt_text(self.prikey, self.thirdkey, message, sign_check)
        self.show_result(final_message, 0, None)

    def decrypt_text(self, message_t):
        _, status, message = decrypt_text(self.prikey, self.pubkey, message_t)
        if   status == -2: self.warnmethod('密文已损坏', 2, 'Error')
        elif status == -1: self.warnmethod('密文解析失败', 2, 'Error')
        elif status >=  0: self.show_result(message, 0, True if status == 0 else False)

    def encrypt_file(self, path_i, path_o, progressbar):
        filename = self.get_user_input('文件名: ', True)

        for step in encrypt_file(self.prikey, self.pubkey, path_i, path_o, filename):
            progressbar['value'] = self.progressbar['value'] + step

        progressbar['value'] = 0
        result_window = self.show_result(path_o, 1, None)

    def decrypt_file(self, path_i, path_o, progressbar):
        for _, status, step in decrypt_file(self.prikey, self.thirdkey, path_i, path_o):
            if   status == -2: self.warnmethod('文件已损坏', 2, 'Error')
            elif status == -1: self.warnmethod('文件信息无效', 2, 'Error')
            elif status ==  0: self.show_result(path_o, 1, True)
            elif status ==  1: self.show_result(path_o, 1, False)
            elif status ==  2: progressbar['value'] = progressbar['value'] + step
        progressbar['value'] = 0


def encrypt_text(self, _prikey, _thirdkey, _message: bytes, _sign: bool) -> str:
    _enc_aes_key, _enc_message = composite_encrypt(_thirdkey, _message)
    _sig = pss_sign(_prikey, _message) if _sign else b'No sig'

    _b64ed_aes_key = base64.b64encode(_enc_aes_key).decode()
    _b64ed_message = base64.b64encode(_enc_message).decode()
    _b64ed_sig = base64.b64encode(_sig).decode()

    return f'{msg_prefix}{_b64ed_aes_key}.{_b64ed_message}.{_b64ed_sig}{msg_suffix}'

def decrypt_text(self, _prikey, _thirdkey, _message: str) -> Tuple[bool, int, str]:
        _message = _message[:-1].replace('\n', '')
        message_t = re.search(r'(?<=-----BEGIN MESSAGE-----).*?(?=-----END MESSAGE-----)', _message)
        if not message_t: return False, -1, ''

        _b64ed_aes_key, _b64ed_message, _b64ed_sig = message_t.group().split('.')
        try:
            _enc_aes_key = base64.b64decode(_b64ed_aes_key.encode())
            _enc_message = base64.b64decode(_b64ed_message.encode())
            _sig = base64.b64decode(_b64ed_sig.encode())
        except binascii.Error: return False, -2, ''

        _message_t = composite_decrypt(_prikey, _enc_message, _enc_aes_key)
        _sig_status = pss_verify(_thirdkey, _message_t, _sig) if _sig != b'No sig' else False
        return True, 0 if _sig_status else 1, _message_t.decode()

def encrypt_file(self, _prikey: RsaKey, _thirdkey: RsaKey, _path_i: str, _path_o: str, _filename: str) -> Generator[float, None, None]:
    _aes_key = get_random_bytes(16)
        
    _file_size = os.path.getsize(_path_i) / 1048576
    _step = 5000 / (_file_size if _file_size >= 1 else 1)

    _sig_hasher = SHA256.new()
    _file_hasher = SHA256.new()

    _file_info = _aes_key + b'^&%&^' + os.path.basename(_path_i).encode()
    _enc_file_info = rsa_encrypt(_thirdkey, _file_info)

    with open(f'{_path_o}/{_filename}.ref', 'wb') as file_out:
        file_out.seek(1024)
        for block, status in read_file(_path_i, 0):
            _sig_hasher.update(block)
            file_out.write(aes_encrypt(_aes_key, block, status))
            yield _step
        _sig = pss_sign(_prikey, None, _sig_hasher)
        _final_file_info = base64.b64encode(_enc_file_info) + b'.' + base64.b64encode(_sig)

        file_out.seek(35, 0)
        file_out.write(str(len(_final_file_info)).encode())
        file_out.write(_final_file_info)
        file_out.seek(0, 0)

        for block, _ in read_file(f'{_path_o}/{_filename}.ref', 35):
            _file_hasher.update(block)
            yield _step

        file_out.write(b'REF')
        file_out.write(_file_hasher.digest())
    return

def decrypt_file(self, _prikey: RsaKey, _thirdkey: RsaKey, _path_i: str, _path_o: str) -> Generator[standard_return, None, None]:
    _file_size = os.path.getsize(_path_i) / 1048576
    _step = 10000 / (_file_size if _file_size >= 1 else 1)

    _sig_hasher = SHA256.new()
    _file_hasher = SHA256.new()

    with open(_path_i, 'rb') as file_in:
        if file_in.read(3) != b'REF': yield False, -1, ''; return

        for block, _ in read_file(_path_i, 35):
            _file_hasher.update(block)

        if file_in.read(32) != _file_hasher.digest(): yield False, -2, ''; return

        _enc_file_info, _sig = file_in.read(int(file_in.read(3))).split(b'.')

    _enc_file_info = base64.b64decode(_enc_file_info)
    _sig = base64.b64decode(_sig)

    try: _file_info = rsa_decrypt(_prikey, _enc_file_info)
    except Exception as E: yield False, -1, str(E); return

    _aes_key, _filename = _file_info.split(b'^&%&^')

    with open(f'{_path_o}/{_filename.decode()}', 'wb') as file_out:
        for enc_block, status in read_file(_path_i, 1024):
            block = aes_decrypt(_aes_key, enc_block, status)
            _sig_hasher.update(block)
            file_out.write(block)
            yield True, 2, _step

    _sig_status = pss_verify(_thirdkey, None, _sig, _sig_hasher)
    yield True, 0 if _sig_status else 1, ''; return

# --------------------------------------------Debug--------------------------------------- #
if __name__ == '__main__':
    pass
