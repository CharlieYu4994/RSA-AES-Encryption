import utils, dialog, os
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import tkinter, sqlite3, threading
from tkinter.simpledialog import askstring
from tkinter import scrolledtext, filedialog, ttk


class MainWindows(tkinter.Tk):
    '''
    主入口
    '''

    thirdkeydict = dict()
    userkeydict = dict()
    thirdkeylist = list()
    userkeylist = list()
    cfg = prikey = pubkey = thirdkey = None

    def __init__(self, _database):
        super().__init__()
        self.database = _database
        self.iconbitmap(dialog.icon)
        self.title('RSA&AES Encryption')
        self.geometry('442x252+200+100')
        self.resizable(0, 0)
        self.getkeylist()
        self.setupUI()

        self.cfg = utils.get_cfg(self.database)
        self.cfg_url_entry.insert('0', self.cfg[0])
        self.dir_save_entry.insert('0', self.cfg[1])
        self.dir_out_entry.insert('0', self.cfg[1])
        if self.thirdkeylist:
            self.select_thirdkey(self.thirdkeylist[0])
            self.thirdkey_ls.current(0)
        if self.userkeylist:
            self.select_userkey(self.cfg[2] if self.cfg[2] else self.userkeylist[0])
            self.userkey_ls.current(0)
        self.wm_attributes('-topmost', 1)

    def setupUI(self):
        tabs = ttk.Notebook(self)

#--------------------------------------------第一页------------------------------------------------#
        page_one = ttk.Frame(tabs)

        self.inputbox = scrolledtext.ScrolledText(page_one, width=46, height=10, takefocus=False)
        self.inputbox.grid(column=0, row=0)

        footbox_page_one = ttk.Frame(page_one)
        self.sign_check = tkinter.BooleanVar()
        signcheck = tkinter.Checkbutton(footbox_page_one, text='签名', variable=self.sign_check, takefocus=False)
        signcheck.grid(column=0, row=0, padx=20)
        text_encrypt_btn = ttk.Button(footbox_page_one, width=16, text='加密', command=self.encrypt_text)
        text_encrypt_btn.grid(column=1, row=0)
        text_decrypt_btn = ttk.Button(footbox_page_one, width=16, text='解密', command=self.decrypt_text)
        text_decrypt_btn.grid(column=2, row=0)
        footbox_page_one.grid(column=0, row=1, pady=10)

        tabs.add(page_one, text='文本加/解密')
#--------------------------------------------第二页------------------------------------------------#
        page_two = ttk.Frame(tabs)

        dirbox = ttk.Frame(page_two)
        dir_in_lab = ttk.Label(dirbox, text='文件路径:')
        dir_in_lab.grid(column=0, row=0, pady=10)
        self.dir_in_entry = ttk.Entry(dirbox, width=28, takefocus=False)
        self.dir_in_entry.grid(column=1, row=0, pady=10)
        dir_in_btn = ttk.Button(dirbox, text='选择文件', width=8,
                             command=lambda: (self.dir_in_entry.delete('0', 'end'),
                             self.dir_in_entry.insert('0', filedialog.askopenfilename(
                             title='请选择文件'))))
        dir_in_btn.grid(column=2, row=0, pady=10)
        dir_out_lab = ttk.Label(dirbox, text='保存路径:')
        dir_out_lab.grid(column=0, row=1, pady=10)
        self.dir_out_entry = ttk.Entry(dirbox, width=28, takefocus=False)
        self.dir_out_entry.grid(column=1, row=1, pady=10)
        dir_out_btn = ttk.Button(dirbox, text='选择目录', width=8,
                             command=lambda: (self.dir_out_entry.delete('0', 'end'),
                             self.dir_out_entry.insert('0', filedialog.askdirectory(
                             title='请选择文件夹').rstrip('/'))))
        dir_out_btn.grid(column=2, row=1)
        dirbox.grid(column=0, row=0, padx=15, pady=15)

        footbox_page_two = ttk.Frame(page_two)
        progressbar_l = ttk.Label(footbox_page_two, text='进度:')
        progressbar_l.grid(column=0, row=0, pady=5)
        self.progressbar = ttk.Progressbar(footbox_page_two, maximum=10000)
        self.progressbar.grid(column=1, row=0, columnspan=19, sticky='ew', pady=5, padx=6)
        self.file_encrypt_btn = ttk.Button(footbox_page_two, width=21, text='加密',
                                    command=lambda: threading.Thread(target=self.encrypt_file).start())
        self.file_encrypt_btn.grid(column=0, columnspan=10, row=1, padx=5)
        self.file_decrypt_btn = ttk.Button(footbox_page_two, width=21, text='解密',
                                    command=lambda: threading.Thread(target=self.decrypt_file).start())
        self.file_decrypt_btn.grid(column=10, columnspan=10, row=1, padx=5)
        footbox_page_two.grid(column=0, row=1, pady=16)

        tabs.add(page_two, text='文件加/解密')
#--------------------------------------------第三页------------------------------------------------#
        page_three = ttk.Frame(tabs)

        footbox_page_three = ttk.Frame(page_three)
        cfg_url_lab = ttk.Label(footbox_page_three, text='服务器 URL:')
        cfg_url_lab.grid(column=0, row=0, pady=8)
        self.cfg_url_entry = ttk.Entry(footbox_page_three, width=35, takefocus=False)
        self.cfg_url_entry.grid(column=1, row=0, pady=8)
        dir_save_lab = ttk.Label(footbox_page_three, text='保存路径    :')
        dir_save_lab.grid(column=0, row=1, pady=8)
        self.dir_save_entry = ttk.Entry(footbox_page_three, width=35, takefocus=False)
        self.dir_save_entry.grid(column=1, row=1, pady=8)
        userkey_ls_lab = ttk.Label(footbox_page_three, text='选择密钥    :')
        userkey_ls_lab.grid(column=0, row=2, pady=8)
        userkey_ls_lab.bind('<Button-1>', lambda event: self.freshkeylist)
        self.userkey_ls = ttk.Combobox(footbox_page_three, width=33, takefocus=False)
        self.userkey_ls['values'] = self.userkeylist
        self.userkey_ls.bind('<<ComboboxSelected>>',
                             lambda event: self.select_userkey(self.userkey_ls.get()))
        self.userkey_ls.grid(column=1, row=2, pady=8)
        footbox_page_three.grid(column=0, row=0, columnspan=10, padx=15, pady=20)

        save_btn = ttk.Button(page_three, width=12, text='保存', command=self.save_cfg)
        save_btn.grid(column=9, row=1)

        btn_box = ttk.Frame(page_three)
        pubkey_btn = ttk.Button(btn_box, width=12, text='生成私钥', command=self.gen_key)
        pubkey_btn.grid(column=0, row=0, padx=4)
        prikey_btn = ttk.Button(btn_box, width=12, text='管理密钥', command=self.keymanage)
        prikey_btn.grid(column=1, row=0, padx=4)
        btn_box.grid(column=0, columnspan=9, row=1, pady=10)

        tabs.add(page_three, text='杂项')
#--------------------------------------------标签栏------------------------------------------------#
        keybox = ttk.Frame(self)
        thirdkey_lab = ttk.Label(keybox, text='收/发件人:')
        thirdkey_lab.grid(column=0, row=0, sticky='w')
        thirdkey_lab.bind('<Button-1>', lambda event: self.freshkeylist)
        self.thirdkey_ls = ttk.Combobox(keybox, width=11)
        self.thirdkey_ls['values'] = self.thirdkeylist
        self.thirdkey_ls.grid(column=1, row=0)
        self.thirdkey_ls.bind('<<ComboboxSelected>>',
                              lambda event: self.select_thirdkey(self.thirdkey_ls.get()))
        keybox.grid(column=0, row=0, sticky='ne', padx=3, pady=1)

        tabs.grid(column=0, row=0)

    def getkeylist(self):
        self.userkeydict = utils.get_keydict('UserKeys', self.database)
        self.thirdkeydict = utils.get_keydict('ThirdKeys', self.database)
        self.userkeylist = list(self.userkeydict.keys())
        self.thirdkeylist = list(self.thirdkeydict.keys())

    def freshkeylist(self):
        self.getkeylist()
        self.thirdkey_ls['values'] = self.thirdkeylist
        self.userkey_ls['values'] = self.userkeylist

    def select_userkey(self, describe: str):
        u_id = self.userkeydict[describe]
        prikey_t, pubkey_t = utils.get_userkey(u_id, self.database)

        for _ in range(5):
            input_window = dialog.InputWindow('密码  :', False)
            self.wait_window(input_window)
            status, prikey, pubkey = utils.load_key(pubkey_t, prikey_t, input_window.result)
            if not status: tkinter.messagebox.showwarning('Warning', '密码错误'); continue
            self.prikey, self.pubkey = prikey, pubkey; break

        if not status:
            tkinter.messagebox.showwarning('Warning', '密码五次输入错误，请重新选择')
            self.userkey_ls.delete(first='0', last='end')

    def select_thirdkey(self, describe):
        u_id = self.thirdkeydict[describe]
        self.thirdkey = utils.load_key(utils.get_thirdkey(u_id, self.database))
    
    def save_cfg(self):
        _url = self.cfg_url_entry.get()
        _outputdir = self.dir_save_entry.get().rstrip('/')
        _defaultkey = self.userkey_ls.get()

        utils.alt_cfg(_url, _outputdir, _defaultkey, self.database)

        self.dir_out_entry.delete('0', 'end')
        self.dir_out_entry.insert('0', _outputdir)

    def keymanage(self):
        keymanage_window = dialog.KeyManage(self.database)
        self.wait_window(keymanage_window)
        self.userkey_ls.delete(first='0', last='end')
        self.freshkeylist()
    
    def gen_key(self):
        input_window = dialog.InputWindow('密码  :', False)
        self.wait_window(input_window)
        prikey, pubkey = utils.gen_rsakey(2048, input_window.result)
        input_window = dialog.InputWindow('描述  :', True)
        self.wait_window(input_window)
        describe = input_window.result if input_window.result else 'UserKey'
        utils.add_userkey(prikey, pubkey, describe, self.database)
        self.freshkeylist()

    def encrypt_text(self):
        message = self.inputbox.get(index1='0.0', index2='end').encode()
        final_message = utils.encrypt_text(self.prikey, self.thirdkey, message, self.sign_check.get())
        dialog.ResultWindow(final_message, 0, None)

    def decrypt_text(self):
        message_t = self.inputbox.get(index1='0.0', index2='end')
        _, status, message = utils.decrypt_text(self.prikey, self.pubkey, message_t)
        if   status == -2: tkinter.messagebox.showerror('Error', '密文已损坏')
        elif status == -1: tkinter.messagebox.showerror('Error', '密文解析失败')
        elif status >=  0: dialog.ResultWindow(message, 0, True if status == 0 else False)

    def encrypt_file(self):
        self.file_encrypt_btn['state'] = 'disabled'

        path_i = self.dir_in_entry.get()
        if self.dir_out_entry.get():
            path_o = self.dir_out_entry.get() 
        else :
            path_o = os.path.dirname(path_i)
            self.dir_out_entry.insert('0', path_o)

        input_window = dialog.InputWindow('文件名:', True)
        self.wait_window(input_window)
        filename = input_window.result

        for step in utils.encrypt_file(self.prikey, self.pubkey, path_i, path_o, filename):
            self.progressbar['value'] = self.progressbar['value'] + step

        self.progressbar['value'] = 0
        self.file_encrypt_btn['state'] = 'normal'
        result_window = dialog.ResultWindow(path_o, 1, None)

    def decrypt_file(self):
        self.file_decrypt_btn['state'] = 'disabled'
        path_i = self.dir_in_entry.get()
        if self.dir_out_entry.get():
            path_o = self.dir_out_entry.get() 
        else :
            path_o = os.path.dirname(path_i)
            self.dir_out_entry.insert('0', path_o)

        for _, status, step in utils.decrypt_file(self.prikey, self.thirdkey, path_i, path_o):
            if   status == -2: tkinter.messagebox.showerror('Error', '文件已损坏')
            elif status == -1: tkinter.messagebox.showerror('Error', '文件信息无效')
            elif status ==  0: dialog.ResultWindow(path_o, 1, True)
            elif status ==  1: dialog.ResultWindow(path_o, 1, False)
            elif status ==  2: self.progressbar['value'] = self.progressbar['value'] + step

        self.progressbar['value'] = 0
        self.file_decrypt_btn['state'] = 'normal'


if __name__ == '__main__':
    utils.gen_database()
    database = sqlite3.connect('keyring.db')
    app = MainWindows(database)
    app.mainloop()
