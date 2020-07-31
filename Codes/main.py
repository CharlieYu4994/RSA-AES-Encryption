import  sqlite3, utils, dialog, cmd


if __name__ == '__main__':
    utils.gen_database()
    database = sqlite3.connect('keyring.db')
    app = dialog.MainWindows(database)
    app.mainloop()
