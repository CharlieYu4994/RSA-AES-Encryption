import tkinter, supports_gui, sqlite3
from tkinter import ttk
from tkinter import scrolledtext


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
        self.tabs = ttk.Notebook(self)

#--------------------------------------------第一页------------------------------------------------#
        self.frame0 = ttk.Frame(self.tabs)

        self.inputbox = scrolledtext.ScrolledText(self.frame0, width=45, height=10)
        self.inputbox.grid(column=0, row=0)

        self.footbox_page1 = ttk.Frame(self.frame0)
        self.signcheck = ttk.Checkbutton(self.footbox_page1, text="签名")
        self.signcheck.grid(column=0, row=0, padx=20)
        self.encryptbtn_t = ttk.Button(self.footbox_page1, width=8, text='加密', command=self.freshkeylist)
        self.encryptbtn_t.grid(column=1, row=0)
        self.decryptbtn_t = ttk.Button(self.footbox_page1, width=8, text='解密')
        self.decryptbtn_t.grid(column=2, row=0)
        self.footbox_page1.grid(column=0, row=1, pady=10)

        self.tabs.add(self.frame0, text="文本加/解密")
#--------------------------------------------第二页------------------------------------------------#
        self.frame1 = ttk.Frame(self.tabs)

        self.dirbox = ttk.Frame(self.frame1)
        self.dir_l_i = ttk.Label(self.dirbox, text='文件路径:')
        self.dir_l_i.grid(column=0, row=0)
        self.dir_e_i = ttk.Entry(self.dirbox, width=25)
        self.dir_e_i.grid(column=1, row=0)
        self.dir_b_i = ttk.Button(self.dirbox, text='选择文件', width=8)
        self.dir_b_i.grid(column=2, row=0)
        self.dir_l_o = ttk.Label(self.dirbox, text='保存路径:')
        self.dir_l_o.grid(column=0, row=1)
        self.dir_e_o = ttk.Entry(self.dirbox, width=25)
        self.dir_e_o.grid(column=1, row=1)
        self.dir_b_o = ttk.Button(self.dirbox, text='选择目录', width=8)
        self.dir_b_o.grid(column=2, row=1)
        self.dirbox.grid(column=0, row=0, padx=16, pady=20)

        self.footbox_page2 = ttk.Frame(self.frame1)
        self.prompt_bar = ttk.Label(self.footbox_page2, text='进度:')
        self.prompt_bar.grid(column=0, row=0, pady=5)
        self.progressbar = ttk.Progressbar(self.footbox_page2)
        self.progressbar.grid(column=1, row=0, columnspan=19,
                         sticky='ew', pady=5, padx=6)
        self.encryptbtn_f = ttk.Button(self.footbox_page2, width=20, text='加密')
        self.encryptbtn_f.grid(column=0, columnspan=10, row=1, padx=5)
        self.decryptbtn_f = ttk.Button(self.footbox_page2, width=20, text='解密')
        self.decryptbtn_f.grid(column=10, columnspan=10, row=1, padx=5)
        self.footbox_page2.grid(column=0, row=1, pady=15)

        self.tabs.add(self.frame1, text="文件加/解密")
#--------------------------------------------第三页------------------------------------------------#
        self.frame2 = ttk.Frame(self.tabs)

        self.footbox_page3 = ttk.Frame(self.frame2)
        self.url_l_cfg = ttk.Label(self.footbox_page3, text='服务器 URL:')
        self.url_l_cfg.grid(column=0, row=0, pady=5)
        self.url_e_cfg = ttk.Entry(self.footbox_page3, width=32)
        self.url_e_cfg.grid(column=1, row=0, pady=5)
        self.save_dir_l = ttk.Label(self.footbox_page3, text='保存路径    :')
        self.save_dir_l.grid(column=0, row=1, pady=5)
        self.save_dir_e = ttk.Entry(self.footbox_page3, width=32)
        self.save_dir_e.grid(column=1, row=1, pady=5)
        self.prikeyls_l = ttk.Label(self.footbox_page3, text='选择密钥    :')
        self.prikeyls_l.grid(column=0, row=2, pady=5)
        self.prikeyls = ttk.Combobox(self.footbox_page3, width=30)
        self.prikeyls['values'] = self.userkeylist
        self.prikeyls.current(0)
        self.prikeyls.grid(column=1, row=2, pady=5)
        self.footbox_page3.grid(column=0, row=0, columnspan=10, padx=10, pady=15)

        self.save_btn = ttk.Button(self.frame2, width=8, text='保存')
        self.save_btn.grid(column=9, row=1)

        self.btn_box = ttk.Frame(self.frame2)
        self.pubkey_btn = ttk.Button(self.btn_box, width=8, text='导入公钥')
        self.pubkey_btn.grid(column=0, row=0, padx=8)
        self.prikey_btn = ttk.Button(self.btn_box, width=8, text='管理密钥', command=self.keymanage)
        self.prikey_btn.grid(column=1, row=0, padx=8)
        self.btn_box.grid(column=0, columnspan=9, row=1, pady=10)

        self.tabs.add(self.frame2, text="杂项")
#--------------------------------------------标签栏------------------------------------------------#
        self.keybox = ttk.Frame(self)
        self.prompt = ttk.Label(self.keybox, text="收件人:")
        self.prompt.grid(column=0, row=0, sticky='w')
        self.pubkeyls = ttk.Combobox(self.keybox, width=12)
        self.pubkeyls['values'] = self.thirdkeylist
        self.pubkeyls.current(0)
        self.pubkeyls.grid(column=1, row=0)
        self.keybox.grid(column=0, row=0, sticky='ne', padx=3, pady=1)

        self.tabs.grid(column=0, row=0)
    
    def getkeylist(self):
        self.userkeydict = supports_gui.get_keydict('UserKeys', self.database)
        self.thirdkeydict = supports_gui.get_keydict('ThirdKeys', self.database)
        self.userkeylist = list(self.userkeydict.keys())
        self.thirdkeylist = list(self.thirdkeydict.keys())

    def freshkeylist(self):
        self.getkeylist()
        self.pubkeyls['values'] = self.thirdkeylist
        self.prikeyls['values'] = self.userkeylist

    def keymanage(self):
        pass

if __name__ == "__main__":
    app = MainWindows()
    app.mainloop()