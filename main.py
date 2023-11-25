import sys
import tkinter as tk
from tkinter import ttk
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from crypto import Crypto
from install import create_database, create_main_password
from models import CredentialModel, SiteModel, UserModel


class LogIn:
    def __init__(self, window, db):
        self.db = db
        self.window = window
        self.main_password_label = ttk.Label(self.window, text="Enter main password:")
        self.main_password_label.pack(padx=5, pady=5, anchor=tk.CENTER)
        self.main_password_textbox = ttk.Entry(self.window, show="*")
        self.main_password_textbox.pack(padx=5, pady=5, anchor=tk.CENTER)
        self.main_password_button = ttk.Button(self.window, text="Log In", command=self.on_click_log_in)
        self.main_password_button.pack(padx=5, pady=5, anchor=tk.CENTER)
        self.message = tk.StringVar()
        self.message_label = ttk.Label(self.window, textvariable=self.message)
        self.message_label.pack(padx=5, pady=5, anchor=tk.CENTER)
        self.user_password = ""

    def check_main_password(self, password):
        with Session(self.db) as session:
            user_model = session.query(UserModel).get(1)

        return user_model.main_password == password

    def on_click_log_in(self):
        self.user_password = self.main_password_textbox.get()
        password_correct = self.check_main_password(self.user_password)

        if password_correct:
            Tab().show_tabs()

        self.message.set("Password incorrect!")


class Tab:

    @staticmethod
    def show_tabs():
        tabsystem = ttk.Notebook(root)
        credentials_tab = ttk.Frame(tabsystem)
        add_credentials_tab = ttk.Frame(tabsystem)
        tabsystem.add(credentials_tab, text="Credentials")
        tabsystem.add(add_credentials_tab, text="Add new")
        tabsystem.pack()
        credentials_list = CredentialsList(credentials_tab, root, db_engine, log_in.user_password, tabsystem)
        AddCredential(add_credentials_tab, db_engine, credentials_list, tabsystem, log_in.user_password)
        log_in.main_password_label.pack_forget()
        log_in.main_password_textbox.pack_forget()
        log_in.main_password_button.pack_forget()
        log_in.message_label.pack_forget()


class AddCredential:
    def __init__(self, tab, db, credentials_list, tabsystem, main_password):
        self.db = db
        self.credentials_list = credentials_list
        self.tabsystem = tabsystem
        self.crypto = Crypto(main_password)

        site_label = ttk.Label(tab, text="Title")
        site_label.grid(row=0, column=0, padx=5, sticky=tk.E)
        self.site_textbox = ttk.Entry(tab)
        self.site_textbox.grid(row=0, column=1, pady=5)

        login_label = ttk.Label(tab, text="Login")
        login_label.grid(row=1, column=0, padx=5, sticky=tk.E)
        self.login_textbox = ttk.Entry(tab)
        self.login_textbox.grid(row=1, column=1, pady=5)

        password_label = ttk.Label(tab, text="Password")
        password_label.grid(row=2, column=0, padx=5, sticky=tk.E)
        self.password_textbox = ttk.Entry(tab, show="*")
        self.password_textbox.grid(row=2, column=1, pady=5)

        button = ttk.Button(tab, text="Add")
        button.grid(row=3, column=1, padx=5)
        button.bind("<Button-1>", self.on_click_add_password)

    def on_click_add_password(self, event):
        with Session(self.db) as session:
            site = self.site_textbox.get()
            site = SiteModel(name=site)
            login = self.login_textbox.get()
            password = self.password_textbox.get()
            password = self.crypto.encrypt(password)
            credential = CredentialModel(site=site, login=login, password=password)
            session.add_all([site, credential])
            session.commit()
            self.clear_textboxes()
            self.credentials_list.load_credentials_to_tree()
            self.tabsystem.select(0)

    def clear_textboxes(self):
        self.site_textbox.delete(0, tk.END)
        self.login_textbox.delete(0, tk.END)
        self.password_textbox.delete(0, tk.END)


class CredentialsList:
    def __init__(self, tab, root_window, db, main_password, tabsystem):
        self.root_window = root_window
        self.db = db
        self.tabsystem = tabsystem
        self.tree = ttk.Treeview(tab, columns=("Title", "Login"), show="headings", height=16)
        self.configure_tree(tab)
        self.crypto = Crypto(main_password)
        self.load_credentials_to_tree()

    def click_on_selected(self, event):
        item = self.tree.selection()[0]
        selection = self.tree.item(item, "values")
        with Session(self.db) as session:
            credential = session.query(CredentialModel).filter(
                SiteModel.name == selection[0],
                CredentialModel.login == selection[1],
                ).one()

            decrypted = self.crypto.decrypt(credential.password)

        self.root_window.clipboard_clear()
        self.root_window.clipboard_append(decrypted)

    def load_credentials_to_tree(self):
        self.tree.delete(*self.tree.get_children())
        with Session(self.db) as session:
            credentials = session.query(CredentialModel).all()
            for credential in credentials:
                self.tree.insert("", "end", values=(credential.site.name, credential.login))

    def configure_tree(self, tab):
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.column("#1", anchor=tk.CENTER, stretch=tk.YES, width=225)
        self.tree.heading("#1", text="Title")
        self.tree.column("#2", anchor=tk.CENTER, stretch=tk.YES, width=202)
        self.tree.heading("#2", text="Login")
        self.tree.bind("<<TreeviewSelect>>", self.click_on_selected)
        self.tree.pack()


if __name__ == '__main__':
    db_engine = create_engine("sqlite:///database.db", echo=False, future=True)

    if len(sys.argv) > 1 and sys.argv[1] == "install":
        create_database(db_engine)
        create_main_password(db_engine)
        quit()

    root = tk.Tk()
    root.title("Password Manager")
    root.resizable(False, False)
    root_width = 450
    root_height = 350
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_offset = int(screen_width / 2 - root_width / 2)
    y_offset = int(screen_height / 2 - root_height / 2)
    root.geometry(f"{root_width}x{root_height}+{x_offset}+{y_offset}")

    log_in = LogIn(root, db_engine)

    root.mainloop()
