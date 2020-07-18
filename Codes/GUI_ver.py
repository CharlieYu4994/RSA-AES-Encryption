import tkinter, supports_gui, sqlite3
from tkinter import ttk
from tkinter.simpledialog import askstring
from tkinter import scrolledtext

class PasswordWindows(tkinter.Toplevel):
    def __init__(self):
        super().__init__()
        self.protocol('WM_DELETE_WINDOW', lambda: self.cancel(None))
        self.title('Password')
        self.geometry('300x100')
        self.resizable(0, 0)
        self.setupUI()

    def setupUI(self):
        password_box = ttk.Frame(self)
        password_l = ttk.Label(password_box, text='密码  :')
        password_l.grid(column=0, row=0)
        self.password_e = ttk.Entry(password_box, width=32)
        self.password_e.grid(column=1, row=0)
        self.password_e.bind("<Return>", self.submit)
        password_box.grid(column=0, row=0, padx=15, pady=15)

        btn_box = ttk.Frame(self)
        o_btn = ttk.Button(btn_box, text="确定", width=16, command=lambda: self.submit(None))
        o_btn.grid(column=0, row=0, padx=12)        
        c_btn = ttk.Button(btn_box, text="取消", width=16, command=lambda: self.cancel(None))
        c_btn.grid(column=1, row=0, padx=12)
        btn_box.grid(column=0, row=1, pady = 10)

    def submit(self, event):
        self.password = self.password_e.get()
        self.destroy()
    
    def cancel(self, enent):
        self.password = None
        self.destroy()

class KeyManage(tkinter.Toplevel):
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
    database = sqlite3.connect('keys.db')
    thirdkeydict = dict() 
    userkeydict = dict()
    thirdkeylist = list()
    userkeylist = list()

    def __init__(self):
        super().__init__()
        self.title('RSA&AES Encryption')
        self.geometry('338x205')
        self.resizable(0, 0)
        self.getkeylist()
        self.setupUI()

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
        self.prikeyls = ttk.Combobox(footbox_page3, width=30)
        self.prikeyls['values'] = self.userkeylist
        self.prikeyls.current(0)
        self.prikeyls.bind("<<ComboboxSelected>>", self.select_prikey)
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
        self.pubkeyls = ttk.Combobox(keybox, width=12)
        self.pubkeyls['values'] = self.thirdkeylist
        self.pubkeyls.current(0)
        self.pubkeyls.grid(column=1, row=0)
        keybox.grid(column=0, row=0, sticky='ne', padx=3, pady=1)

        tabs.grid(column=0, row=0)
    
    def getkeylist(self):
        self.userkeydict = supports_gui.get_keydict('UserKeys', self.database)
        self.thirdkeydict = supports_gui.get_keydict('ThirdKeys', self.database)
        self.userkeylist = list(self.userkeydict.keys())
        self.thirdkeylist = list(self.thirdkeydict.keys())

    def freshkeylist(self):
        self.getkeylist()
        self.pubkeyls['values'] = self.thirdkeylist
        self.prikeyls['values'] = self.userkeylist
    
    def select_prikey(self, event):
        _id = self.userkeydict[self.prikeyls.get()]
        _prikey, _pubkey = supports_gui.get_userkey(_id, self.database)
        passwordwindows = PasswordWindows()
        self.wait_window(passwordwindows)
        print(passwordwindows.password)

    def keymanage(self):
        pass

    def encrypt_t(self):
        message = self.inputbox.get(index1='0.0', index2='end')
        print(self.getkey(self.pubkeyls.get(), _is_user=True))
        #enc_aes_key, enc_message = supports_gui.rsa_encrypt(, message[:-1].encode())
        #self.sign_check.get()


if __name__ == "__main__":
    app = MainWindows()
    app.mainloop()
