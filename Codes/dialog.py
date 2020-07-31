import tkinter, sys, os, utils, re, pyperclip
from tkinter.simpledialog import askstring
from tkinter import scrolledtext, filedialog, ttk

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
        self.userkeydict = utils.get_keydict('UserKeys', self.database)
        self.thirdkeydict = utils.get_keydict('ThirdKeys', self.database)
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
        utils.del_key(u_id, 'UserKeys' if key_type == 0 else 'ThirdKeys', self.database)
        keylist.delete('active')
    
    def rename(self, key_type: int):
        u_id = self.get_u_id(key_type)
        keylist = self.userkey_ls if key_type == 0 else self.thirdkey_ls
        input_window = InputWindow('描述  :', True)
        self.wait_window(input_window)
        describe = input_window.result if input_window.result else keylist.get('active')[:-4]
        utils.alt_key(u_id, 'Describe', describe, 'UserKeys' if key_type == 0 else 'ThirdKeys',
                         self.database)
        self.freshkeylist()

    def alt_pass(self):
        u_id = self.get_u_id(0)
        prikey_t, pubkey_t = utils.get_userkey(u_id, self.database)

        for _ in range(5):
            input_window = InputWindow('旧密码:', False)
            self.wait_window(input_window)
            status, prikey, _ = utils.load_key(pubkey_t, prikey_t, input_window.result)
            if not status: tkinter.messagebox.showwarning('Warning', '密码错误'); continue
            break
        if not status:
            tkinter.messagebox.showwarning('Warning', '密码五次输入错误，请重新选择'); return
        input_window = InputWindow('新密码:', False)
        self.wait_window(input_window)
        password = input_window.result
        utils.alt_key(u_id, 'PriKey', utils.expert_key(prikey, password).decode(),
                         'UserKeys', self.database)

    def import_key(self, path: str):
        with open(path, 'rb') as file_in:
            temp = file_in.read(1048576).decode()
            prikey = re.search(r'-----BEGIN RSA[\s\S]*PRIVATE KEY-----', temp)
            pubkey = re.search(r'-----BEGIN PUBLIC[\s\S]*BLIC KEY-----', temp)
            input_window = InputWindow('描述  :', True)
            self.wait_window(input_window)
            if prikey and pubkey:
                utils.add_userkey(prikey.group().encode(), pubkey.group().encode(),
                                     input_window.result, self.database)
            elif not prikey and pubkey:
                utils.add_thirdkey(pubkey.group().encode(), input_window.result, self.database)
            else:
                tkinter.messagebox.showerror('Error', '密钥格式无效')
            self.freshkeylist()
        
    def export_key(self, key_type, path: str):
        with open(path, 'w') as file_out:
            u_id = self.get_u_id(key_type)
            if key_type == 0:
                _, pubkey = utils.get_userkey(u_id, self.database)
                file_out.write(pubkey.decode())
            else:
                pubkey = utils.get_thirdkey(u_id, self.database).decode()
                file_out.write(pubkey)
    
    def export_pri_key(self, path: str):
        with open(path, 'wb') as file_out:
            u_id = self.get_u_id(0)
            prikey, pubkey = utils.get_userkey(u_id, self.database)
            file_out.write(prikey)
            file_out.write(pubkey)

    def get_u_id(self, key_type: int):
        keylist = self.userkey_ls if key_type == 0 else self.thirdkey_ls
        keydict = self.userkeydict if key_type == 0 else self.thirdkeydict
        return keydict[keylist.get('active')]

