import tkinter, supports, sqlite3, pyperclip, re
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from tkinter.simpledialog import askstring
from tkinter import scrolledtext, filedialog, ttk
import base64, os

msg_prefix = '-----BEGIN MESSAGE-----\n'
msg_suffix = '\n-----END MESSAGE-----'


class InputWindow(tkinter.Toplevel):
    '''
    密码输入窗口
    '''
    
    password = None

    def __init__(self):
        super().__init__()
        displayh = self.winfo_screenheight() // 2
        dispalyw = self.winfo_screenwidth() // 2
        self.protocol('WM_DELETE_WINDOW', lambda: self.destroy())
        self.title('Password')
        self.geometry(f'300x100+{dispalyw-150}+{displayh-100}')
        self.resizable(0, 0)
        self.setupUI()
        self.password_e.focus_set()

    def setupUI(self):
        password_box = ttk.Frame(self)
        password_l = ttk.Label(password_box, text='密码  :')
        password_l.grid(column=0, row=0)
        self.password_e = ttk.Entry(password_box, width=32)
        self.password_e.grid(column=1, row=0)
        self.password_e['show'] = '*'
        self.password_e.bind('<Return>', self.submit)
        password_box.grid(column=0, row=0, padx=15, pady=15)

        btn_box = ttk.Frame(self)
        o_btn = ttk.Button(btn_box, text='确定', width=16, command=lambda: self.submit(None))
        o_btn.grid(column=0, row=0, padx=12)        
        c_btn = ttk.Button(btn_box, text='取消', width=16, command=lambda: self.destroy())
        c_btn.grid(column=1, row=0, padx=12)
        btn_box.grid(column=0, row=1, pady=10)

    def submit(self, event):
        self.password = self.password_e.get()
        self.destroy()


class ResultWindow(tkinter.Toplevel):
    '''
    结果显示窗口
    '''

    result = ''

    def __init__(self, _result: str, _type: int, _sig_status=True):
        super().__init__()
        displayh = self.winfo_screenheight() // 2
        dispalyw = self.winfo_screenwidth() // 2
        self.result = _result
        self.sig_status = _sig_status
        self.title('Result')
        self.geometry(f'338x180+{dispalyw-150}+{displayh-200}')
        self.resizable(0, 0)
        if   _type == 0: self.setupUI_E()
        elif _type == 1: self.setupUI_D()


    def setupUI_E(self):
        self.setup_result_box()

        clipbrd_btn = ttk.Button(self, text='复制', width=10, command=lambda: pyperclip.copy(self.result))
        clipbrd_btn.grid(column=0, row=1, pady=10)

        ok_btn = ttk.Button(self, text='确定', width=10, command=lambda: self.destroy())
        ok_btn.grid(column=1, row=1, pady=10)
    
    def setupUI_D(self):
        self.setup_result_box()

        sign_l = ttk.Label(self, text='√ 签名有效' if self.sig_status else '× 签名无效')
        sign_l.grid(column=0, row=1)

        ok_btn = ttk.Button(self, text='确定', width=10, command=lambda: self.destroy())
        ok_btn.grid(column=1, row=1, pady=10)
    
    def setup_result_box(self):
        textbox = scrolledtext.ScrolledText(self, width=45, height=10)
        textbox.grid(column=0, row=0, columnspan=2)
        textbox.insert('0.0', self.result)


class KeyManage(tkinter.Toplevel):
    '''
    密钥管理窗口
    '''

    database = sqlite3.connect('keyring.db')

    def __init__(self):
        super().__init__()
        self.title('KeyManager')
        self.geometry('200x200')
        self.resizable(0, 0)
        self.setupUI()

    def setupUI(self):

        pass


class MainWindows(tkinter.Tk):
    '''
    主入口
    '''

    database = sqlite3.connect('keyring.db')
    thirdkeydict = dict()
    userkeydict = dict()
    thirdkeylist = list()
    userkeylist = list()
    prikey = pubkey = thirdkey = None

    def __init__(self):
        super().__init__()
        self.title('RSA&AES Encryption')
        self.geometry('345x205')
        self.resizable(0, 0)
        self.getkeylist()
        self.setupUI()
        if self.thirdkeylist:
            self.select_thirdkey(self.thirdkeylist[0])
            self.thirdkey_ls.current(0)
        if self.userkeylist:
            self.select_userkey(self.userkeylist[0])
            self.userkey_ls.current(0)

    def setupUI(self):
        tabs = ttk.Notebook(self)

#--------------------------------------------第一页------------------------------------------------#
        frame0 = ttk.Frame(tabs)

        self.inputbox = scrolledtext.ScrolledText(frame0, width=46, height=10)
        self.inputbox.grid(column=0, row=0)

        footbox_page1 = ttk.Frame(frame0)
        self.sign_check = tkinter.BooleanVar()
        signcheck = ttk.Checkbutton(footbox_page1, text='签名', variable=self.sign_check)
        signcheck.grid(column=0, row=0, padx=20)
        encrypt_b_text = ttk.Button(footbox_page1, width=8, text='加密', command=self.encrypt_text)
        encrypt_b_text.grid(column=1, row=0)
        decrypt_b_text = ttk.Button(footbox_page1, width=8, text='解密', command=self.decrypt_text)
        decrypt_b_text.grid(column=2, row=0)
        footbox_page1.grid(column=0, row=1, pady=10)

        tabs.add(frame0, text='文本加/解密')
#--------------------------------------------第二页------------------------------------------------#
        frame1 = ttk.Frame(tabs)

        dirbox = ttk.Frame(frame1)
        dir_l_i = ttk.Label(dirbox, text='文件路径:')
        dir_l_i.grid(column=0, row=0, pady=10)
        self.dir_e_i = ttk.Entry(dirbox, width=25)
        self.dir_e_i.grid(column=1, row=0, pady=10)
        dir_b_i = ttk.Button(dirbox, text='选择文件', width=8,\
            command=lambda:(self.dir_e_i.delete('0', 'end'), self.dir_e_i.insert('0',\
                filedialog.askopenfilename(title='请选择文件'))))
        dir_b_i.grid(column=2, row=0, pady=10)
        dir_l_o = ttk.Label(dirbox, text='保存路径:')
        dir_l_o.grid(column=0, row=1, pady=10)
        self.dir_e_o = ttk.Entry(dirbox, width=25)
        self.dir_e_o.grid(column=1, row=1, pady=10)
        dir_b_o = ttk.Button(dirbox, text='选择目录', width=8,\
            command=lambda:(self.dir_e_o.delete('0', 'end'), self.dir_e_o.insert('0',\
                filedialog.askdirectory(title='请选择文件夹'))))
        dir_b_o.grid(column=2, row=1, pady=10)
        dirbox.grid(column=0, row=0, padx=20, pady=15)

        footbox_page2 = ttk.Frame(frame1)
        encrypt_b_file = ttk.Button(footbox_page2, width=20, text='加密', command=self.encrypt_file)
        encrypt_b_file.grid(column=0, columnspan=10, row=1, padx=5)
        decrypt_b_file = ttk.Button(footbox_page2, width=20, text='解密', command=self.decrypt_file)
        decrypt_b_file.grid(column=10, columnspan=10, row=1, padx=5)
        footbox_page2.grid(column=0, row=1, pady=10)

        tabs.add(frame1, text='文件加/解密')
#--------------------------------------------第三页------------------------------------------------#
        frame2 = ttk.Frame(tabs)

        footbox_page3 = ttk.Frame(frame2)
        url_l_cfg = ttk.Label(footbox_page3, text='服务器 URL:')
        url_l_cfg.grid(column=0, row=0, pady=5)
        self.url_e_cfg = ttk.Entry(footbox_page3, width=32)
        self.url_e_cfg.grid(column=1, row=0, pady=5)
        dir_l_save = ttk.Label(footbox_page3, text='保存路径    :')
        dir_l_save.grid(column=0, row=1, pady=5)
        self.dir_e_save = ttk.Entry(footbox_page3, width=32)
        self.dir_e_save.grid(column=1, row=1, pady=5)
        userkey_ls_l = ttk.Label(footbox_page3, text='选择密钥    :')
        userkey_ls_l.grid(column=0, row=2, pady=5)
        userkey_ls_l.bind('<Button-1>', self.freshkeylist)
        self.userkey_ls = ttk.Combobox(footbox_page3, width=30)
        self.userkey_ls['values'] = self.userkeylist
        self.userkey_ls.bind('<<ComboboxSelected>>', lambda event: self.select_userkey(self.userkey_ls.get()))
        self.userkey_ls.grid(column=1, row=2, pady=5)
        footbox_page3.grid(column=0, row=0, columnspan=10, padx=16, pady=15)

        save_btn = ttk.Button(frame2, width=8, text='保存')
        save_btn.grid(column=9, row=1)

        btn_box = ttk.Frame(frame2)
        pubkey_btn = ttk.Button(btn_box, width=8, text='导入公钥')
        pubkey_btn.grid(column=0, row=0, padx=8)
        prikey_btn = ttk.Button(btn_box, width=8, text='管理密钥', command=self.keymanage)
        prikey_btn.grid(column=1, row=0, padx=8)
        btn_box.grid(column=0, columnspan=9, row=1, pady=10)

        tabs.add(frame2, text='杂项')
#--------------------------------------------标签栏------------------------------------------------#
        keybox = ttk.Frame(self)
        prompt = ttk.Label(keybox, text='收/发件人:')
        prompt.grid(column=0, row=0, sticky='w')
        prompt.bind('<Button-1>', self.freshkeylist)
        self.thirdkey_ls = ttk.Combobox(keybox, width=11)
        self.thirdkey_ls['values'] = self.thirdkeylist
        self.thirdkey_ls.grid(column=1, row=0)
        self.thirdkey_ls.bind('<<ComboboxSelected>>', lambda event: self.select_thirdkey(self.thirdkey_ls.get()))
        keybox.grid(column=0, row=0, sticky='ne', padx=3, pady=1)

        tabs.grid(column=0, row=0)
    
    def getkeylist(self):
        self.userkeydict = supports.get_keydict('UserKeys', self.database)
        self.thirdkeydict = supports.get_keydict('ThirdKeys', self.database)
        self.userkeylist = list(self.userkeydict.keys())
        self.thirdkeylist = list(self.thirdkeydict.keys())

    def freshkeylist(self, event):
        self.getkeylist()
        self.pubkeyls['values'] = self.thirdkeylist
        self.prikeyls['values'] = self.userkeylist
    
    def select_userkey(self, _describe: str):
        _id = self.userkeydict[_describe]
        _prikey_t, _pubkey_t = supports.get_userkey(_id, self.database)
        for _ in range(5):
            _inputwindow = InputWindow()
            self.wait_window(_inputwindow)
            _status, _prikey, _pubkey = supports.load_key(_pubkey_t, _prikey_t, _inputwindow.password)
            if _status: self.prikey = _prikey; self.pubkey = _pubkey; break
            tkinter.messagebox.showwarning('Warning','密码错误')
        if not _status:
            tkinter.messagebox.showerror('Error','密码五次输入错误，请重新选择')
            self.userkey_ls.delete(first='0', last='end')
    
    def select_thirdkey(self, _describe):
        _id = self.thirdkeydict[_describe]
        self.thirdkey = supports.load_key(supports.get_thirdkey(_id, self.database))

    def keymanage(self):
        pass

    def encrypt_text(self):
        message = self.inputbox.get(index1='0.0', index2='end')[:-1].encode()
        enc_aes_key, enc_message = supports.composite_encrypt(self.thirdkey, message)
        sig = supports.pss_sign(self.prikey, message) if self.sign_check.get() else b'No sig'

        b64ed_aes_key = base64.b64encode(enc_aes_key).decode()
        b64ed_message = base64.b64encode(enc_message).decode()
        b64ed_sig = base64.b64encode(sig).decode()

        final_message = f'{msg_prefix}{b64ed_aes_key}.{b64ed_message}.{b64ed_sig}{msg_suffix}'
        resultwindow = ResultWindow(final_message, 0)
    
    def decrypt_text(self):
        message_t = self.inputbox.get(index1='0.0', index2='end')[:-1].replace('\n', '')
        message_t = re.search(r'(?<=-----BEGIN MESSAGE-----).*?(?=-----END MESSAGE-----)', message_t)
        if not message_t: tkinter.messagebox.showwarning('Warning','密文解析失败'); return

        b64ed_aes_key, b64ed_message, b64ed_sig = message_t.group().split('.')
        enc_aes_key = base64.b64decode(b64ed_aes_key.encode())
        enc_message = base64.b64decode(b64ed_message.encode())
        sig = base64.b64decode(b64ed_sig.encode())

        message = supports.composite_decrypt(self.prikey, enc_message, enc_aes_key)
        status = supports.pss_verify(self.thirdkey, message, sig) if sig != b'No sig' else False
        resultwindow = ResultWindow(message, 1, status)
    
    def encrypt_file(self):
        aes_key = get_random_bytes(16)
        path_i = self.dir_e_i.get()
        path_o = self.dir_e_o.get()
        hasher = SHA256.new()

        file_info = aes_key + b'^&%&^' + os.path.basename(path_i).encode()
        enc_file_info = supports.rsa_encrypt(self.thirdkey, file_info)

        with open(f'{path_o}/result.ref', 'wb') as file_out:
            file_out.seek(500)
            for block, status in supports.read_file(path_i, 0):
                hasher.update(block)
                file_out.write(supports.aes_encrypt(aes_key, block, status))
            sig = supports.pss_sign(self.prikey, None, hasher)
            final_file_info = base64.b64encode(enc_file_info) + b'.' + base64.b64encode(sig)

            file_out.seek(0, 0)
            file_out.write(b'REF')
            file_out.write(hasher.digest())
            file_out.write(str(len(final_file_info)).encode())
            file_out.write(final_file_info)
        
        resultwindow = ResultWindow(f'文件路径为：{path_o}', 0)
    
    def decrypt_file(self):
        path_i = self.dir_e_i.get()
        path_o = self.dir_e_o.get()
        hasher = SHA256.new()

        try:
            with open(path_i, 'rb') as file_in:
                sign = file_in.read(3)
                file_hash = file_in.read(32)
                enc_file_info, sig = file_in.read(int(file_in.read(3))).split(b'.')

            if sign != b'REF':
                tkinter.messagebox.showerror('Warning','文件解析失败')
                return

            enc_file_info = base64.b64decode(enc_file_info)
            sig = base64.b64decode(sig)
            file_info = supports.rsa_decrypt(self.prikey, enc_file_info)
        except Exception as E:
            tkinter.messagebox.showerror('Warning','文件信息解密失败'); return

        aes_key, filename = file_info.split(b'^&%&^')

        with open(f'{path_o}/{filename.decode()}', 'wb') as file_out:
            for enc_block, status in supports.read_file(path_i, 500):
                block = supports.aes_decrypt(aes_key, enc_block, status)
                hasher.update(block)
                file_out.write(block)
        
        if file_hash != hasher.digest():
            tkinter.messagebox.showwarning('Warning','文件损坏')
            return

        sig_status = supports.pss_verify(self.pubkey, None, sig, hasher)
        resultwindow = ResultWindow(f'文件路径为：{path_o}', 1, sig_status)


if __name__ == '__main__':
    if not os.path.exists('keyring.db'): supports.gen_database()
    app = MainWindows()
    app.mainloop()
