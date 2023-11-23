import sys
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import Credential, Site
from install import install
from crypto import Crypto
from cryptography.fernet import InvalidToken


@dataclass
class DTOCredential:
    title: str
    login: str


class AddPassword:
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
        button.bind("<Button-1>", self.on_click)

    def on_click(self, event):
        with Session(self.db) as session:
            site = self.site_textbox.get()
            site = Site(name=site)
            login = self.login_textbox.get()
            password = self.crypto.encrypt(self.password_textbox.get())
            credential = Credential(site=site, login=login, password=password)
            session.add_all([site, credential])
            session.commit()
            self.credentials_list.load_credentials_to_tree()
            self.tabsystem.select(0)


class CredentialsList:
    def __init__(self, tab, root_window, db, main_password, tabsystem, main_password_tab):
        self.root_window = root_window
        self.db = db
        self.tabsystem = tabsystem
        self.main_password_tab = main_password_tab
        self.tree = ttk.Treeview(tab, columns=("Title", "Login"), show="headings", height=15)
        self.configure_tree()
        self.crypto = Crypto(main_password)
        self.tree.bind("<<TreeviewSelect>>", self.on_click)
        self.load_credentials_to_tree()

    def on_click(self, event):
        item = self.tree.selection()[0]
        selection = self.tree.item(item, "values")
        with Session(self.db) as session:
            credential = session.query(Credential).filter(
                Site.name == selection[0],
                Credential.login == selection[1],
                ).one()

            try:
                decrypted = self.crypto.decrypt(credential.password)
            except InvalidToken:
                self.tree.pack_forget()
                self.tabsystem.add(self.main_password_tab, text="Log In")
                self.tabsystem.select(self.main_password_tab)
                return

        self.root_window.clipboard_clear()
        self.root_window.clipboard_append(decrypted)

    def load_credentials_to_tree(self):
        with Session(self.db) as session:
            credentials = session.query(Credential).all()
            for credential in credentials:
                self.tree.insert("", "end", values=(credential.site.name, credential.login))

    def configure_tree(self):
        self.tree.column("#1", anchor=tk.CENTER, stretch=tk.YES, width=175)
        self.tree.heading("#1", text="Title")
        self.tree.column("#2", anchor=tk.CENTER, stretch=tk.YES, width=175)
        self.tree.heading("#2", text="Login")
        self.tree.pack()


if __name__ == '__main__':
    def pass_on_click():
        tabsystem = ttk.Notebook(root)
        main_password_tab = ttk.Frame(tabsystem)
        credentials_tab = ttk.Frame(tabsystem)
        add_credentials_tab = ttk.Frame(tabsystem)
        tabsystem.add(credentials_tab, text="Credentials")
        tabsystem.add(add_credentials_tab, text="Add new")
        tabsystem.pack(expand=True, fill="both")
        credentials_list = CredentialsList(credentials_tab, root, engine, main_password_textbox.get(), tabsystem, main_password_tab)
        AddPassword(add_credentials_tab, engine, credentials_list, tabsystem, main_password_textbox.get())
        main_password_label.pack_forget()
        main_password_textbox.pack_forget()
        main_password_button.pack_forget()

    root = tk.Tk()
    root.title("Password Manager")
    root.resizable(False, False)
    root_width = 350
    root_height = 350
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_offset = int(screen_width / 2 - root_width / 2)
    y_offset = int(screen_height / 2 - root_height / 2)
    root.geometry(f"{root_width}x{root_height}+{x_offset}+{y_offset}")

    main_password_label = ttk.Label(root, text="Enter main password:")
    main_password_label.pack(padx=5, pady=5)
    main_password_textbox = ttk.Entry(root, show="*")
    main_password_textbox.pack(padx=5, pady=5)
    main_password_button = ttk.Button(root, text="Log In", command=pass_on_click)
    main_password_button.pack(padx=5, pady=5)

    engine = create_engine("sqlite:///database.db", echo=False, future=True)

    if len(sys.argv) > 1 and sys.argv[1] == "install":
        install(engine)
        print("Database with tables has been created successfully.")
        quit()

    root.mainloop()
