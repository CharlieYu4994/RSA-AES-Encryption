import tkinter
from tkinter import ttk
from tkinter import scrolledtext


class KeyManage(tkinter.Toplevel):
    def __init__(self):
        super().__init__()
        self.title('KeyManager')
        self.geometry('200x200')
        self.resizable(0, 0)
        self.setupUI

    def setupUI(self):
        pass


class MainWindows(tkinter.Tk):
    keylist = [1]

    def __init__(self):
        super().__init__()
        self.title('RSA&AES Encryption')
        self.geometry('338x205')
        self.resizable(0, 0)
        self.setupUI()

    def setupUI(self):
        tabs = ttk.Notebook(self)

#--------------------------------------------第一页------------------------------------------------#
        frame0 = ttk.Frame(tabs)

        inputbox = scrolledtext.ScrolledText(frame0, width=45, height=10)
        inputbox.grid(column=0, row=0)

        footbox_page1 = ttk.Frame(frame0)
        signcheck = ttk.Checkbutton(footbox_page1, text="签名")
        signcheck.grid(column=0, row=0, padx=20)
        encryptbtn_t = ttk.Button(footbox_page1, width=8, text='加密')
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
        dir_e_i = ttk.Entry(dirbox, width=25)
        dir_e_i.grid(column=1, row=0)
        dir_b_i = ttk.Button(dirbox, text='选择文件', width=8)
        dir_b_i.grid(column=2, row=0)
        dir_l_o = ttk.Label(dirbox, text='保存路径:')
        dir_l_o.grid(column=0, row=1)
        dir_e_o = ttk.Entry(dirbox, width=25)
        dir_e_o.grid(column=1, row=1)
        dir_b_o = ttk.Button(dirbox, text='选择目录', width=8)
        dir_b_o.grid(column=2, row=1)
        dirbox.grid(column=0, row=0, padx=16, pady=20)

        footbox_page2 = ttk.Frame(frame1)
        prompt_bar = ttk.Label(footbox_page2, text='进度:')
        prompt_bar.grid(column=0, row=0, pady=5)
        progressbar = ttk.Progressbar(footbox_page2)
        progressbar.grid(column=1, row=0, columnspan=19,
                         sticky='ew', pady=5, padx=6)
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
        url_l_cfg.grid(column=0, row=0, pady=8)
        url_e_cfg = ttk.Entry(footbox_page3, width=32)
        url_e_cfg.grid(column=1, row=0, pady=8)
        save_dir_l = ttk.Label(footbox_page3, text='保存路径    :')
        save_dir_l.grid(column=0, row=1, pady=8)
        save_dir_e = ttk.Entry(footbox_page3, width=32)
        save_dir_e.grid(column=1, row=1, pady=8)
        footbox_page3.grid(column=0, row=0, columnspan=10, padx=8, pady=20)

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
        keybox.grid(column=0, row=0, sticky='ne', padx=3, pady=1)
        prompt = ttk.Label(keybox, text="收件人:")
        prompt.grid(column=0, row=0, sticky='w')
        keyls = ttk.Combobox(keybox, width=10)
        keyls['values'] = self.keylist
        keyls.current(0)
        keyls.grid(column=1, row=0)

        tabs.grid(column=0, row=0)
    def keymanage(self):
        pass

if __name__ == "__main__":
    app = MainWindows()
    app.mainloop()