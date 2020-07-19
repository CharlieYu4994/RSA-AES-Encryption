import tkinter, supports_gui, sqlite3, pyperclip
from tkinter import ttk
from tkinter.simpledialog import askstring
from tkinter import scrolledtext
import base64


class InputWindow(tkinter.Toplevel):
    '''
    密码输入窗口
    '''

    def __init__(self):
        super().__init__()
        displayh = self.winfo_screenheight() // 2
        dispalyw = self.winfo_screenwidth() // 2
        self.protocol('WM_DELETE_WINDOW', lambda: self.cancel(None))
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
        self.password_e.bind("<Return>", self.submit)
        password_box.grid(column=0, row=0, padx=15, pady=15)

        btn_box = ttk.Frame(self)
        o_btn = ttk.Button(btn_box, text="确定", width=16, command=lambda: self.submit(None))
        o_btn.grid(column=0, row=0, padx=12)        
        c_btn = ttk.Button(btn_box, text="取消", width=16, command=lambda: self.cancel(None))
        c_btn.grid(column=1, row=0, padx=12)
        btn_box.grid(column=0, row=1, pady=10)

    def submit(self, event):
        self.password = self.password_e.get()
        self.destroy()
    
    def cancel(self, enent):
        self.password = None
        self.destroy()

class ResultWindow(tkinter.Toplevel):
    '''
    结果显示窗口
    '''

    result = ''

    def __init__(self, _result: str):
        super().__init__()
        displayh = self.winfo_screenheight() // 2
        dispalyw = self.winfo_screenwidth() // 2
        self.result = _result
        self.title('Result')
        self.geometry(f'338x180+{dispalyw-150}+{displayh-200}')
        self.resizable(0, 0)
        self.setupUI()

    def setupUI(self):
        textbox = scrolledtext.ScrolledText(self, width=45, height=10)
        textbox.grid(column=0, row=0, columnspan=2)
        textbox.insert('0.0', self.result)

        clipbrd_btn = ttk.Button(self, text='复制', width=10, command=lambda: pyperclip.copy(self.result))
        clipbrd_btn.grid(column=0, row=1, pady=10)

        ok_btn = ttk.Button(self, text='确定', width=10, command=lambda: self.destroy())
        ok_btn.grid(column=1, row=1, pady=10)


class KeyManage(tkinter.Toplevel):
    '''
    密钥管理窗口
    '''

    database = sqlite3.connect('keys.db')

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

    database = sqlite3.connect('keys.db')
    thirdkeydict = dict()
    userkeydict = dict()
    thirdkeylist = list()
    userkeylist = list()
    prikey = pubkey = thirdkey = None

    def __init__(self):
        super().__init__()
        self.title('RSA&AES Encryption')
        self.geometry('338x205')
        self.resizable(0, 0)
        self.getkeylist()
        self.setupUI()
        if self.thirdkeylist:
            self.select_thirdkey(self.thirdkeylist[0])
            self.pubkeyls.current(0)
        if self.userkeylist:
            self.select_prikey(self.userkeylist[0])
            self.prikeyls.current(0)

    def setupUI(self):
        tabs = ttk.Notebook(self)

#--------------------------------------------第一页------------------------------------------------#
        frame0 = ttk.Frame(tabs)

        self.inputbox = scrolledtext.ScrolledText(frame0, width=45, height=10)
        self.inputbox.grid(column=0, row=0)

        footbox_page1 = ttk.Frame(frame0)
        self.sign_check = tkinter.BooleanVar()
        signcheck = ttk.Checkbutton(footbox_page1, text="签名", variable=self.sign_check)
        signcheck.grid(column=0, row=0, padx=20)
        encryptbtn_t = ttk.Button(footbox_page1, width=8, text='加密', command=self.encrypt_t)
        encryptbtn_t.grid(column=1, row=0)
        decryptbtn_t = ttk.Button(footbox_page1, width=8, text='解密')
        decryptbtn_t.grid(column=2, row=0)
        footbox_page1.grid(column=0, row=1, pady=10)

        tabs.add(frame0, text="文本加/解密")
#--------------------------------------------第二页------------------------------------------------#
        frame1 = ttk.Frame(tabs)

        dirbox = ttk.Frame(frame1)
        dir_l_i = ttk.Label(dirbox, text='文件路径:')
        dir_l_i.grid(column=0, row=0)
        self.dir_e_i = ttk.Entry(dirbox, width=25)
        self.dir_e_i.grid(column=1, row=0)
        dir_b_i = ttk.Button(dirbox, text='选择文件', width=8)
        dir_b_i.grid(column=2, row=0)
        dir_l_o = ttk.Label(dirbox, text='保存路径:')
        dir_l_o.grid(column=0, row=1)
        self.dir_e_o = ttk.Entry(dirbox, width=25)
        self.dir_e_o.grid(column=1, row=1)
        dir_b_o = ttk.Button(dirbox, text='选择目录', width=8)
        dir_b_o.grid(column=2, row=1)
        dirbox.grid(column=0, row=0, padx=16, pady=20)

        footbox_page2 = ttk.Frame(frame1)
        prompt_bar = ttk.Label(footbox_page2, text='进度:')
        prompt_bar.grid(column=0, row=0, pady=5)
        self.progressbar = ttk.Progressbar(footbox_page2)
        self.progressbar.grid(column=1, row=0, columnspan=19, sticky='ew', pady=5, padx=6)
        encryptbtn_f = ttk.Button(footbox_page2, width=20, text='加密')
        encryptbtn_f.grid(column=0, columnspan=10, row=1, padx=5)
        decryptbtn_f = ttk.Button(footbox_page2, width=20, text='解密')
        decryptbtn_f.grid(column=10, columnspan=10, row=1, padx=5)
        footbox_page2.grid(column=0, row=1, pady=15)

        tabs.add(frame1, text="文件加/解密")
#--------------------------------------------第三页------------------------------------------------#
        frame2 = ttk.Frame(tabs)

        footbox_page3 = ttk.Frame(frame2)
        url_l_cfg = ttk.Label(footbox_page3, text='服务器 URL:')
        url_l_cfg.grid(column=0, row=0, pady=5)
        self.url_e_cfg = ttk.Entry(footbox_page3, width=32)
        self.url_e_cfg.grid(column=1, row=0, pady=5)
        save_dir_l = ttk.Label(footbox_page3, text='保存路径    :')
        save_dir_l.grid(column=0, row=1, pady=5)
        self.save_dir_e = ttk.Entry(footbox_page3, width=32)
        self.save_dir_e.grid(column=1, row=1, pady=5)
        prikeyls_l = ttk.Label(footbox_page3, text='选择密钥    :')
        prikeyls_l.grid(column=0, row=2, pady=5)
        prikeyls_l.bind('<Button-1>', self.freshkeylist)
        self.prikeyls = ttk.Combobox(footbox_page3, width=30)
        self.prikeyls['values'] = self.userkeylist
        self.prikeyls.bind("<<ComboboxSelected>>", lambda event: self.select_prikey(self.prikeyls.get()))
        self.prikeyls.grid(column=1, row=2, pady=5)
        footbox_page3.grid(column=0, row=0, columnspan=10, padx=10, pady=15)

        save_btn = ttk.Button(frame2, width=8, text='保存')
        save_btn.grid(column=9, row=1)

        btn_box = ttk.Frame(frame2)
        pubkey_btn = ttk.Button(btn_box, width=8, text='导入公钥')
        pubkey_btn.grid(column=0, row=0, padx=8)
        prikey_btn = ttk.Button(btn_box, width=8, text='管理密钥', command=self.keymanage)
        prikey_btn.grid(column=1, row=0, padx=8)
        btn_box.grid(column=0, columnspan=9, row=1, pady=10)

        tabs.add(frame2, text="杂项")
#--------------------------------------------标签栏------------------------------------------------#
        keybox = ttk.Frame(self)
        prompt = ttk.Label(keybox, text="收件人:")
        prompt.grid(column=0, row=0, sticky='w')
        prompt.bind('<Button-1>', self.freshkeylist)
        self.pubkeyls = ttk.Combobox(keybox, width=12)
        self.pubkeyls['values'] = self.thirdkeylist
        self.pubkeyls.grid(column=1, row=0)
        self.pubkeyls.bind('<<ComboboxSelected>>', lambda event: self.select_thirdkey(self.pubkeyls.get()))
        keybox.grid(column=0, row=0, sticky='ne', padx=3, pady=1)

        tabs.grid(column=0, row=0)
    
    def getkeylist(self):
        self.userkeydict = supports_gui.get_keydict('UserKeys', self.database)
        self.thirdkeydict = supports_gui.get_keydict('ThirdKeys', self.database)
        self.userkeylist = list(self.userkeydict.keys())
        self.thirdkeylist = list(self.thirdkeydict.keys())

    def freshkeylist(self, event):
        self.getkeylist()
        self.pubkeyls['values'] = self.thirdkeylist
        self.prikeyls['values'] = self.userkeylist
    
    def select_prikey(self, _describe: str):
        _id = self.userkeydict[_describe]
        _prikey_t, _pubkey_t = supports_gui.get_userkey(_id, self.database)
        for _ in range(5):
            _inputwindow = InputWindow()
            self.wait_window(_inputwindow)
            _status, _prikey, _pubkey = supports_gui.load_key(_pubkey_t, _prikey_t, _inputwindow.password)
            if _status: self.prikey = _prikey; self.pubkey = _pubkey; break
            tkinter.messagebox.showwarning('Warning','密码错误')
        if not _status:
            tkinter.messagebox.showerror('Error','密码五次输入错误，请重新选择')
            self.prikeyls.delete(first='0', last='end')
    
    def select_thirdkey(self, _describe):
        _id = self.userkeydict[_describe]
        self.thirdkey = supports_gui.load_key(supports_gui.get_thirdkey(_id, self.database))

    def keymanage(self):
        pass

    def encrypt_t(self):
        message = self.inputbox.get(index1='0.0', index2='end')[:-1].encode()
        enc_aes_key, enc_message = supports_gui.rsa_encrypt(self.thirdkey, message)
        sig = supports_gui.pss_sign(self.prikey, message) if self.sign_check.get() else b'No sig'
        b64ed_aes_key = base64.b64encode(enc_aes_key).decode()
        b64ed_message = base64.b64encode(enc_message).decode()
        b64ed_sig = base64.b64encode(sig).decode()
        final_message = f'{b64ed_aes_key}.{b64ed_message}.{b64ed_sig}'
        resultwindow = ResultWindow(final_message)
    
    def decrypt_t(self):
        message = self.inputbox.get(index1='0.0', index2='end')[:-1].encode()


if __name__ == "__main__":
    app = MainWindows()
    app.mainloop()
