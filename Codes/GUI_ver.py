import tkinter
from tkinter import ttk
from tkinter import scrolledtext

class MainLoop(tkinter.Tk):
    keylist = [1]

    def __init__(self):
        super().__init__()
        self.title('RSA&AES Encryption')
        self.geometry('338x205')
        self.resizable(0,0)
        self.setupUI()

    def setupUI(self):
        tabs = ttk.Notebook(self)

#--------------------------------------------第一页------------------------------------------------#
        frame0 = ttk.Frame(tabs)

        inputbox = scrolledtext.ScrolledText(frame0, width=45, height=10)
        inputbox.grid(column=0, row=0)

        footbox0 = ttk.Frame(frame0)
        footbox0.grid(column=0, row=1, pady=10)

        signcheck = ttk.Checkbutton(footbox0, text = "签名")
        signcheck.grid(column=5, row=0, padx=20)

        rightbox0 = ttk.Frame(footbox0)
        rightbox0.grid(column=6, row=0)

        encryptbtn_t = ttk.Button(rightbox0, width=8, text='加密')
        encryptbtn_t.grid(column=0, row=0)

        decryptbtn_t = ttk.Button(rightbox0, width=8, text='解密')
        decryptbtn_t.grid(column=1, row=0)

#--------------------------------------------第二页------------------------------------------------#
        frame1 = ttk.Frame(tabs)
        
        rightbox1 = ttk.Frame(frame1)
        rightbox1.grid(column=1, row=0)

        encryptbtn_f = ttk.Button(rightbox1, width=8, text='加密')
        encryptbtn_f.grid(column=0, row=0)

        decryptbtn_f = ttk.Button(rightbox1, width=8, text='解密')
        decryptbtn_f.grid(column=1, row=0)

#--------------------------------------------第三页------------------------------------------------#
        frame2 = ttk.Frame(tabs)

#--------------------------------------------标签栏------------------------------------------------#
        keybox = ttk.Frame(self)
        keybox.grid(column=0, row=0, sticky = tkinter.NE, padx=3, pady=1)

        prompt = ttk.Label(keybox, text="收件人:")
        prompt.grid(column=0, row=0, sticky = tkinter.W)

        keyls = ttk.Combobox(keybox, width=10)
        keyls['values'] = self.keylist
        keyls.current(0)
        keyls.grid(column=1, row=0)

        tabs.add(frame0, text="文本加/解密")
        tabs.add(frame1, text="文件加/解密")
        tabs.add(frame2, text="设置")
        tabs.grid(column=0, row=0)

if __name__ == "__main__":
    app = MainLoop()
    app.mainloop()

