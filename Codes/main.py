import supports, sys
import re, os, base64, binascii, pyperclip
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import tkinter, sqlite3, threading
from tkinter.simpledialog import askstring
from tkinter import scrolledtext, filedialog, ttk

msg_prefix = '-----BEGIN MESSAGE-----\n'
msg_suffix = '\n-----END MESSAGE-----'

if getattr(sys, 'frozen', None):
    basedir = sys._MEIPASS
else:
    basedir = os.path.dirname(__file__)

icon = os.path.join(basedir, 'assets/icon.ico')

class InputWindow(tkinter.Toplevel):
    '''
    输入窗口
    '''

    result = None

    def __init__(self, prompt: str, show: bool):
        super().__init__()
        displayh = self.winfo_screenheight() // 2
        dispalyw = self.winfo_screenwidth() // 2
        self.prompt = prompt
        self.show = not show
        self.iconbitmap(icon)
        self.protocol('WM_DELETE_WINDOW', lambda: self.destroy())
        self.title('Input')
        self.geometry(f'374x110+{dispalyw-187}+{displayh-90}')
        self.resizable(0, 0)
        self.setupUI()
        self.grab_set()
        self.wm_attributes('-topmost', 1)

    def setupUI(self):
        result_box = ttk.Frame(self)
        result_l = ttk.Label(result_box, text=self.prompt)
        result_l.grid(column=0, row=0)
        self.result_entry = ttk.Entry(result_box, width=32)
        self.result_entry.grid(column=1, row=0)
        if self.show: self.result_entry['show'] = '*'
        self.result_entry.bind('<Return>', lambda event: self.submit())
        self.result_entry.focus_set()
        result_box.grid(column=0, row=0, padx=15, pady=15)

        btn_box = ttk.Frame(self)
        o_btn = ttk.Button(btn_box, text='确定', width=16, command=lambda: self.submit())
        o_btn.grid(column=0, row=0, padx=16)
        c_btn = ttk.Button(btn_box, text='取消', width=16, command=lambda: self.destroy())
        c_btn.grid(column=1, row=0, padx=16)
        btn_box.grid(column=0, row=1, pady=12)

    def submit(self):
        self.result = self.result_entry.get()
        self.destroy()


class ResultWindow(tkinter.Toplevel):
    '''
    结果显示窗口
    '''

    result = ''

    def __init__(self, _result: str, _type: int, sig_status=True):
        super().__init__()
        self.displayh = self.winfo_screenheight() // 2
        self.dispalyw = self.winfo_screenwidth() // 2
        self.result = _result
        self.sig_status = sig_status
        self.iconbitmap(icon)
        self.title('Result')

        if   _type == 0: self.setupUI_T()
        elif _type == 1: self.setupUI_F()

        self.resizable(0, 0)

    def setupUI_T(self):
        self.geometry(f'385x225+{self.dispalyw-192}+{self.displayh-150}')

        textbox = scrolledtext.ScrolledText(self, width=40, height=10)
        textbox.grid(column=0, row=0, columnspan=2)
        textbox.insert('0.0', self.result)

        ok_btn = ttk.Button(self, text='确定', width=16, command=lambda: self.destroy())
        ok_btn.grid(column=1, row=1, pady=10)

        if self.sig_status == None:
            copy_btn = ttk.Button(self, text='复制', width=16, command=lambda: pyperclip.copy(self.result))
            copy_btn.grid(column=0, row=1, pady=10)
        else:
            sign_l = ttk.Label(self, text='√ 签名有效' if self.sig_status else '× 签名无效',
                           foreground='green' if self.sig_status else 'red',
                           font=('', '12'))
            sign_l.grid(column=0, row=1)

    def setupUI_F(self):
        self.geometry(f'383x125+{self.dispalyw-191}+{self.displayh-120}')
        textbox = tkinter.Text(self, width=42, height=4)
        textbox.grid(column=0, row=0, columnspan=3)
        textbox.insert('0.0', self.result)

        path = self.result.replace('/', '\\')
        open_btn = ttk.Button(self, text='打开', width=16 if self.sig_status == None else 10,
                              command=lambda: os.system(f"explorer {path}"))
        ok_btn = ttk.Button(self, text='确定', width=16 if self.sig_status == None else 10,
                            command=lambda: self.destroy())

        if self.sig_status == None:
            open_btn.grid(column=0, row=1, pady=10, padx=10)
            ok_btn.grid(column=1, row=1, pady=10, padx=10)
        else:
            sign_l = ttk.Label(self, text='√ 签名有效' if self.sig_status else '× 签名无效',
                            foreground='green' if self.sig_status else 'red',
                            font=('', '12'))
            sign_l.grid(column=0, row=1, pady=10)
            open_btn.grid(column=1, row=1, pady=10)
            ok_btn.grid(column=2, row=1, pady=10)


class KeyManage(tkinter.Toplevel):
    '''
    密钥管理窗口
    '''

    thirdkeydict = dict()
    userkeydict = dict()
    thirdkeylist = list()
    userkeylist = list()

    def __init__(self, _database):
        super().__init__()
        self.database = _database
        displayh = self.winfo_screenheight() // 2
        dispalyw = self.winfo_screenwidth() // 2
        self.iconbitmap(icon)
        self.title('KeyManager')
        self.geometry(f'370x300+{dispalyw-185}+{displayh-150}')
        self.resizable(0, 0)
        self.setupUI()
        self.freshkeylist()
        self.grab_set()

    def setupUI(self):
        self.tabs = ttk.Notebook(self)
        
        page_one = ttk.Frame(self.tabs)
        userkey_ls_sb = ttk.Scrollbar(page_one)
        self.userkey_ls = tkinter.Listbox(page_one, width=38,
                                          yscrollcommand=userkey_ls_sb.set)
        self.userkey_ls.grid(column=0, row=0)
        self.userkey_ls.bind('<Double-Button-1>', lambda event: self.rename(0))
        self.userkey_ls.bind('<Return>', lambda event: self.alt_pass())
        self.userkey_ls.bind('<Shift-KeyPress-Return>',
                             lambda event: self.export_pri_key(
                             filedialog.asksaveasfilename(
                             defaultextension='.pem', filetypes=[('PEM Key', '*.pem')])))
        userkey_ls_sb.grid(column=1, row=0, sticky='ns')
        userkey_ls_sb.config(command=self.userkey_ls.yview)
        btn_box_page_one = ttk.Frame(page_one)
        del_btn_page_one = ttk.Button(btn_box_page_one, text='删除', command=
                                      lambda: self.del_key(0))
        del_btn_page_one.grid(column=0, row=0, padx=5)
        import_btn_page_one = ttk.Button(btn_box_page_one, text='导入', command=
                                        lambda: self.import_key(filedialog.askopenfilename(
                                        defaultextension='.pem', filetypes=[('PEM Key', '*.pem')])))
        import_btn_page_one.grid(column=1, row=0, padx=5)
        export_btn_page_one = ttk.Button(btn_box_page_one, text='导出', command=
                                        lambda: self.export_key(0, filedialog.asksaveasfilename(
                                        defaultextension='.pem', filetypes=[('PEM Key', '*.pem')])))
        export_btn_page_one.grid(column=2, row=0, padx=5)
        btn_box_page_one.grid(column=0, row=1, columnspan=2, pady=14)
        self.tabs.add(page_one, text='私钥')

        page_two = ttk.Frame(self.tabs)
        thirdkey_ls_sb = ttk.Scrollbar(page_two)
        self.thirdkey_ls = tkinter.Listbox(page_two, width=38,
                                           yscrollcommand=thirdkey_ls_sb.set)
        self.thirdkey_ls.bind('<Double-Button-1>', lambda event: self.rename(1))
        self.thirdkey_ls.grid(column=0, row=0)
        thirdkey_ls_sb.grid(column=1, row=0, sticky='ns')
        thirdkey_ls_sb.config(command=self.thirdkey_ls.yview)
        btn_box_page_two = ttk.Frame(page_two)
        del_btn_page_two = ttk.Button(btn_box_page_two, text='删除', command=
                                      lambda: self.del_key(1))
        del_btn_page_two.grid(column=0, row=0, padx=5)
        import_btn_page_two = ttk.Button(btn_box_page_two, text='导入', command=
                                        lambda: self.import_key(filedialog.askopenfilename(
                                        defaultextension='.pem', filetypes=[('PEM Key', '*.pem')])))
        import_btn_page_two.grid(column=1, row=0, padx=5)
        export_btn_page_two = ttk.Button(btn_box_page_two, text='导出', command=
                                        lambda: self.export_key(1, filedialog.asksaveasfilename(
                                        defaultextension='.pem', filetypes=[('PEM Key', '*.pem')])))
        export_btn_page_two.grid(column=2, row=0, padx=5)
        btn_box_page_two.grid(column=0, row=1, columnspan=2, pady=14)
        self.tabs.add(page_two, text='公钥')

        self.tabs.grid(column=0, row=0, sticky='nswe')

    def getkeylist(self):
        self.userkeydict = supports.get_keydict('UserKeys', self.database)
        self.thirdkeydict = supports.get_keydict('ThirdKeys', self.database)
        self.userkeylist = list(self.userkeydict.keys())
        self.thirdkeylist = list(self.thirdkeydict.keys())

    def freshkeylist(self):
        self.getkeylist()
        self.userkey_ls.delete('0', 'end')
        self.thirdkey_ls.delete('0', 'end')
        for key in self.userkeylist:
            self.userkey_ls.insert('end', key)
        for key in self.thirdkeylist:
            self.thirdkey_ls.insert('end', key)

    def del_key(self, key_type: int):
        u_id = self.get_u_id(key_type)
        keylist = self.userkey_ls if key_type == 0 else self.thirdkey_ls
        supports.del_key(u_id, 'UserKeys' if key_type == 0 else 'ThirdKeys', self.database)
        keylist.delete('active')
    
    def rename(self, key_type: int):
        u_id = self.get_u_id(key_type)
        keylist = self.userkey_ls if key_type == 0 else self.thirdkey_ls
        input_window = InputWindow('描述  :', True)
        self.wait_window(input_window)
        describe = input_window.result if input_window.result else keylist.get('active')[:-4]
        supports.alt_key(u_id, 'Describe', describe, 'UserKeys' if key_type == 0 else 'ThirdKeys',
                         self.database)
        self.freshkeylist()

    def alt_pass(self):
        u_id = self.get_u_id(0)
        prikey_t, pubkey_t = supports.get_userkey(u_id, self.database)

        for _ in range(5):
            input_window = InputWindow('旧密码:', False)
            self.wait_window(input_window)
            status, prikey, _ = supports.load_key(pubkey_t, prikey_t, input_window.result)
            if not status: tkinter.messagebox.showwarning('Warning', '密码错误'); continue
            break
        if not status:
            tkinter.messagebox.showwarning('Warning', '密码五次输入错误，请重新选择'); return
        input_window = InputWindow('新密码:', False)
        self.wait_window(input_window)
        password = input_window.result
        supports.alt_key(u_id, 'PriKey', supports.expert_key(prikey, password).decode(),
                         'UserKeys', self.database)

    def import_key(self, path: str):
        with open(path, 'rb') as file_in:
            temp = file_in.read(1048576).decode()
            prikey = re.search(r'-----BEGIN RSA[\s\S]*PRIVATE KEY-----', temp)
            pubkey = re.search(r'-----BEGIN PUBLIC[\s\S]*BLIC KEY-----', temp)
            input_window = InputWindow('描述  :', True)
            self.wait_window(input_window)
            if prikey and pubkey:
                supports.add_userkey(prikey.group().encode(), pubkey.group().encode(),
                                     input_window.result, self.database)
            elif not prikey and pubkey:
                supports.add_thirdkey(pubkey.group().encode(), input_window.result, self.database)
            else:
                tkinter.messagebox.showerror('Error', '密钥格式无效')
            self.freshkeylist()
        
    def export_key(self, key_type, path: str):
        with open(path, 'w') as file_out:
            u_id = self.get_u_id(key_type)
            if key_type == 0:
                _, pubkey = supports.get_userkey(u_id, self.database)
                file_out.write(pubkey.decode())
            else:
                pubkey = supports.get_thirdkey(u_id, self.database).decode()
                file_out.write(pubkey)
    
    def export_pri_key(self, path: str):
        with open(path, 'wb') as file_out:
            u_id = self.get_u_id(0)
            prikey, pubkey = supports.get_userkey(u_id, self.database)
            file_out.write(prikey)
            file_out.write(pubkey)

    def get_u_id(self, key_type: int):
        keylist = self.userkey_ls if key_type == 0 else self.thirdkey_ls
        keydict = self.userkeydict if key_type == 0 else self.thirdkeydict
        return keydict[keylist.get('active')]


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
        self.iconbitmap(icon)
        self.title('RSA&AES Encryption')
        self.geometry('442x252+200+100')
        self.resizable(0, 0)
        self.getkeylist()
        self.setupUI()

        self.cfg = supports.get_cfg(self.database)
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
        self.userkeydict = supports.get_keydict('UserKeys', self.database)
        self.thirdkeydict = supports.get_keydict('ThirdKeys', self.database)
        self.userkeylist = list(self.userkeydict.keys())
        self.thirdkeylist = list(self.thirdkeydict.keys())

    def freshkeylist(self):
        self.getkeylist()
        self.thirdkey_ls['values'] = self.thirdkeylist
        self.userkey_ls['values'] = self.userkeylist

    def select_userkey(self, describe: str):
        u_id = self.userkeydict[describe]
        prikey_t, pubkey_t = supports.get_userkey(u_id, self.database)

        for _ in range(5):
            input_window = InputWindow('密码  :', False)
            self.wait_window(input_window)
            status, prikey, pubkey = supports.load_key(pubkey_t, prikey_t, input_window.result)
            if not status: tkinter.messagebox.showwarning('Warning', '密码错误'); continue
            self.prikey, self.pubkey = prikey, pubkey; break

        if not status:
            tkinter.messagebox.showwarning('Warning', '密码五次输入错误，请重新选择')
            self.userkey_ls.delete(first='0', last='end')

    def select_thirdkey(self, describe):
        u_id = self.thirdkeydict[describe]
        self.thirdkey = supports.load_key(supports.get_thirdkey(u_id, self.database))
    
    def save_cfg(self):
        _url = self.cfg_url_entry.get()
        _outputdir = self.dir_save_entry.get().rstrip('/')
        _defaultkey = self.userkey_ls.get()

        supports.alt_cfg(_url, _outputdir, _defaultkey, self.database)

        self.dir_out_entry.delete('0', 'end')
        self.dir_out_entry.insert('0', _outputdir)

    def keymanage(self):
        keymanage_window = KeyManage(self.database)
        self.wait_window(keymanage_window)
        self.userkey_ls.delete(first='0', last='end')
        self.freshkeylist()
    
    def gen_key(self):
        input_window = InputWindow('密码  :', False)
        self.wait_window(input_window)
        prikey, pubkey = supports.gen_rsakey(2048, input_window.result)
        input_window = InputWindow('描述  :', True)
        self.wait_window(input_window)
        describe = input_window.result if input_window.result else 'UserKey'
        supports.add_userkey(prikey, pubkey, describe, self.database)
        self.freshkeylist()

    def encrypt_text(self):
        message = self.inputbox.get(index1='0.0', index2='end').encode()
        enc_aes_key, enc_message = supports.composite_encrypt(self.thirdkey, message)
        sig = supports.pss_sign(self.prikey, message) if self.sign_check.get() else b'No sig'

        b64ed_aes_key = base64.b64encode(enc_aes_key).decode()
        b64ed_message = base64.b64encode(enc_message).decode()
        b64ed_sig = base64.b64encode(sig).decode()

        final_message = f'{msg_prefix}{b64ed_aes_key}.{b64ed_message}.{b64ed_sig}{msg_suffix}'
        result_window = ResultWindow(final_message, 0, None)

    def decrypt_text(self):
        message_t = self.inputbox.get(index1='0.0', index2='end')[
            :-1].replace('\n', '')
        message_t = re.search(
            r'(?<=-----BEGIN MESSAGE-----).*?(?=-----END MESSAGE-----)', message_t)
        if not message_t:
            tkinter.messagebox.showerror('Error', '密文解析失败')
            return

        b64ed_aes_key, b64ed_message, b64ed_sig = message_t.group().split('.')
        try:
            enc_aes_key = base64.b64decode(b64ed_aes_key.encode())
            enc_message = base64.b64decode(b64ed_message.encode())
            sig = base64.b64decode(b64ed_sig.encode())
        except binascii.Error:
            tkinter.messagebox.showerror('Error', '密文已损坏')
            return

        message = supports.composite_decrypt(
            self.prikey, enc_message, enc_aes_key)
        sig_status = supports.pss_verify(
            self.thirdkey, message, sig) if sig != b'No sig' else False
        result_window = ResultWindow(message.decode(), 0, sig_status)

    def encrypt_file(self):
        self.file_encrypt_btn['state'] = 'disabled'
        aes_key = get_random_bytes(16)
        path_i = self.dir_in_entry.get()
        if self.dir_out_entry.get():
            path_o = self.dir_out_entry.get() 
        else :
            os.path.dirname(path_i)
            self.dir_out_entry.insert('0', path_o)
        
        file_size = os.path.getsize(path_i) / 1048576
        step = 5000 / (file_size if file_size >= 1 else 1)

        sig_hasher = SHA256.new()
        file_hasher = SHA256.new()

        file_info = aes_key + b'^&%&^' + os.path.basename(path_i).encode()
        enc_file_info = supports.rsa_encrypt(self.thirdkey, file_info)

        input_window = InputWindow('文件名:', True)
        self.wait_window(input_window)

        with open(f'{path_o}/{input_window.result}.ref', 'wb') as file_out:
            file_out.seek(1024)
            for block, status in supports.read_file(path_i, 0):
                sig_hasher.update(block)
                file_out.write(supports.aes_encrypt(aes_key, block, status))
                self.progressbar['value'] = self.progressbar['value'] + step
            sig = supports.pss_sign(self.prikey, None, sig_hasher)
            final_file_info = base64.b64encode(enc_file_info) + b'.' + base64.b64encode(sig)

            file_out.seek(35, 0)
            file_out.write(str(len(final_file_info)).encode())
            file_out.write(final_file_info)
            file_out.seek(0, 0)

            for block, _ in supports.read_file(f'{path_o}/{input_window.result}.ref', 35):
                file_hasher.update(block)
                self.progressbar['value'] = self.progressbar['value'] + step

            file_out.write(b'REF')
            file_out.write(file_hasher.digest())

        self.progressbar['value'] = 0
        self.file_encrypt_btn['state'] = 'normal'
        result_window = ResultWindow(path_o, 1, None)

    def decrypt_file(self):
        self.file_decrypt_btn['state'] = 'disabled'
        path_i = self.dir_in_entry.get()
        path_o = self.dir_out_entry.get()

        file_size = os.path.getsize(path_i) / 1048576
        step = 10000 / (file_size if file_size >= 1 else 1)

        sig_hasher = SHA256.new()
        file_hasher = SHA256.new()

        with open(path_i, 'rb') as file_in:
            if file_in.read(3) != b'REF':
                tkinter.messagebox.showerror('Error', '文件解析失败')
                self.file_decrypt_btn['state'] = 'normal'; return

            for block, _ in supports.read_file(path_i, 35):
                file_hasher.update(block)

            if file_in.read(32) != file_hasher.digest():
                tkinter.messagebox.showerror('Error', '文件损坏')
                self.file_decrypt_btn['state'] = 'normal'; return

            enc_file_info, sig = file_in.read(int(file_in.read(3))).split(b'.')

        enc_file_info = base64.b64decode(enc_file_info)
        sig = base64.b64decode(sig)

        try: file_info = supports.rsa_decrypt(self.prikey, enc_file_info)
        except Exception as E:
            tkinter.messagebox.showerror('Error', '文件信息解密失败')
            self.file_decrypt_btn['state'] = 'normal'; return

        aes_key, filename = file_info.split(b'^&%&^')

        with open(f'{path_o}/{filename.decode()}', 'wb') as file_out:
            for enc_block, status in supports.read_file(path_i, 1024):
                block = supports.aes_decrypt(aes_key, enc_block, status)
                sig_hasher.update(block)
                file_out.write(block)
                self.progressbar['value'] = self.progressbar['value'] + step

        sig_status = supports.pss_verify(self.pubkey, None, sig, sig_hasher)
        self.progressbar['value'] = 0
        self.file_decrypt_btn['state'] = 'normal'
        result_window = ResultWindow(path_o, 1, sig_status)


if __name__ == '__main__':
    supports.gen_database()
    database = sqlite3.connect('keyring.db')
    app = MainWindows(database)
    app.mainloop()
