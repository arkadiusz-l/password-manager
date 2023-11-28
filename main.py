import sys
import tkinter as tk
from tkinter import ttk
from hashlib import sha1
from random import choices, shuffle
from string import ascii_letters, punctuation
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound
from install import create_database
from models import CredentialModel, UserModel
from crypto import Crypto


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

    @staticmethod
    def calculate_password_hash(password):
        password = password.encode("utf-8")
        password_hash = sha1(password).hexdigest()
        return password_hash

    def check_main_password(self, password):
        password_hash = self.calculate_password_hash(password)
        with Session(self.db) as session:
            user_model = session.query(UserModel).get(1)
            password_hash_from_db = user_model.main_password

        return password_hash_from_db == password_hash

    def on_click_log_in(self):
        self.user_password = self.main_password_textbox.get()
        password_correct = self.check_main_password(self.user_password)
        if password_correct:
            Tab().show_tabs()

        self.message.set("Password incorrect!")


class Tab:

    def show_tabs(self):
        tabsystem = ttk.Notebook(root)
        credentials_tab = ttk.Frame(tabsystem)
        add_credentials_tab = ttk.Frame(tabsystem)
        tabsystem.add(credentials_tab, text="Credentials")
        tabsystem.add(add_credentials_tab, text="Add new")
        tabsystem.pack()
        credentials_list = CredentialsList(credentials_tab, root, db_engine, log_in.user_password, tabsystem)
        AddCredential(add_credentials_tab, db_engine, credentials_list, tabsystem, log_in.user_password)
        self.clear_tab()

    @staticmethod
    def clear_tab():
        log_in.main_password_label.destroy()
        log_in.main_password_textbox.destroy()
        log_in.main_password_button.destroy()
        log_in.message_label.destroy()


class AddCredential:
    def __init__(self, tab, db, credentials_list, tabsystem, main_password):
        self.db = db
        self.credentials_list = credentials_list
        self.tabsystem = tabsystem
        self.crypto = Crypto(main_password)

        title_label = ttk.Label(tab, text="Title:")
        title_label.grid(row=0, column=0, padx=5, sticky=tk.E)
        self.title_textbox = ttk.Entry(tab)
        self.title_textbox.grid(row=0, column=1, pady=5)

        login_label = ttk.Label(tab, text="Login:")
        login_label.grid(row=1, column=0, padx=5, sticky=tk.E)
        self.login_textbox = ttk.Entry(tab)
        self.login_textbox.grid(row=1, column=1, pady=5)

        password_label = ttk.Label(tab, text="Password:")
        password_label.grid(row=2, column=0, padx=5, sticky=tk.E)
        self.password_textbox = ttk.Entry(tab, show="*")
        self.password_textbox.grid(row=2, column=1, pady=5)

        generate_button = ttk.Button(tab, text="Generate")
        generate_button.grid(row=2, column=2, padx=10)
        generate_button.bind("<Button-1>", self.on_click_generate)

        add_button = ttk.Button(tab, text="Add")
        add_button.grid(row=3, column=1, padx=5)
        add_button.bind("<Button-1>", self.on_click_add_credential)

        self.message = tk.StringVar()
        self.message_label = ttk.Label(tab, textvariable=self.message)
        self.message_label.grid(row=4, column=1)

    def on_click_add_credential(self, event):
        title = self.title_textbox.get()
        login = self.login_textbox.get()
        password = self.password_textbox.get()
        try:
            self.credentials_list.get_credential_from_db(title, login)
            self.message.set("The given pair of title + login already exists!")
        except NoResultFound:
            password = self.crypto.encrypt(password)
            with Session(self.db) as session:
                credential = CredentialModel(title=title, login=login, password=password)
                session.add(credential)
                session.commit()
            self.tabsystem.select(0)
            self.clear_tab()
            self.credentials_list.load_credentials_to_tree()

    def clear_tab(self):
        self.title_textbox.delete(0, tk.END)
        self.login_textbox.delete(0, tk.END)
        self.password_textbox.delete(0, tk.END)
        self.message.set("")

    @staticmethod
    def generate_password(letters, digits, specials):
        all_letters = ascii_letters
        all_digits = "".join(map(str, range(0, 10)))
        all_special_characters = punctuation
        password = choices(population=all_digits, k=digits)
        password += choices(population=all_letters, k=letters)
        password += choices(population=all_special_characters, k=specials)
        shuffle(password)
        password = "".join(password)
        return password

    def on_click_generate(self, event):
        password = self.generate_password(letters=5, digits=2, specials=1)
        self.password_textbox.delete(0, tk.END)
        self.password_textbox.insert(0, password)


class CredentialsList:
    def __init__(self, tab, root_window, db, main_password, tabsystem):
        self.root_window = root_window
        self.db = db
        self.tabsystem = tabsystem
        self.tree = ttk.Treeview(tab, columns=("Title", "Login"), show="headings", height=16)
        self.configure_tree(tab)
        self.crypto = Crypto(main_password)
        self.load_credentials_to_tree()

    def get_credential_from_db(self, title, login):
        with Session(self.db) as session:
            return session.query(CredentialModel).filter(
                CredentialModel.title == title,
                CredentialModel.login == login,
            ).one()

    def click_on_selected(self, event):
        item = self.tree.selection()[0]
        selection = self.tree.item(item, "values")
        title = selection[0]
        login = selection[1]
        credential = self.get_credential_from_db(title, login)
        decrypted = self.crypto.decrypt(credential.password)

        self.root_window.clipboard_clear()
        self.root_window.clipboard_append(decrypted)

    def load_credentials_to_tree(self):
        self.tree.delete(*self.tree.get_children())
        with Session(self.db) as session:
            credentials = session.query(CredentialModel).all()
            for credential in credentials:
                self.tree.insert("", "end", values=(credential.title, credential.login))

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
    def install():
        if len(sys.argv) > 1 and sys.argv[1] == "install":
            create_database(db_engine)
            main_password = input("Enter main password:\n")
            main_password_hash = LogIn.calculate_password_hash(main_password)

            with Session(db_engine) as session:
                user = UserModel(id=1, main_password=main_password_hash)
                session.add(user)
                session.commit()
            print("Main password saved successfully.")
            quit()

    db_engine = create_engine("sqlite:///database.db", echo=False, future=True)
    install()

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
