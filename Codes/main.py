import  sqlite3, sys, utils, dialog, cmd


if __name__ == '__main__':
    utils.gen_database()
    database = sqlite3.connect('keyring.db')
    if len(sys.argv) < 2:
        app = dialog.MainWindows(database)
        app.mainloop()
    elif sys.argv[1] == '-c':
        cmd.command_mode(database)
