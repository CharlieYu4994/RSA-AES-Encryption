import  sqlite3, sys, utils, dialog


if __name__ == '__main__':
    utils.gen_database()
    database = sqlite3.connect('keyring.db')
    if len(sys.argv) < 2:
        app = dialog.MainWindows(database)
        app.mainloop()
