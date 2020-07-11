from tkinter import Button, Checkbutton, Frame, Label, Tk, scrolledtext
from tkinter.ttk import Combobox

window = Tk()
window.title('RSA&AES Encryption')
window.geometry('398x200')
window.resizable(0,0) 

inputbox = scrolledtext.ScrolledText(window, width=54, height=10)
inputbox.grid(column=0, row=0)

actionbox = Frame(window)
actionbox.grid(column=0, row=1)

space = Label(actionbox)
space.grid(columnspan=3, row=0)

cfgbtn = Button(actionbox, text='修改配置', relief='groove')
cfgbtn.grid(column=2, row=1)

encryptbtn = Button(actionbox, text='加密', relief='groove')
encryptbtn.grid(column=3, row=1)

signcheck = Checkbutton(actionbox, text = "是否签名")
signcheck.grid(column=1, row=1)

combo = Combobox(actionbox)
combo['values'] = [1]
combo.current(0)
combo.grid(column=0, row=1)

window.mainloop()
