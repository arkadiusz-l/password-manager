import sys
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import Credential, Site
from install import install


@dataclass
class DTOCredential:
    title: str
    login: str


class AddPassword:
    def __init__(self, tab, db, credentials_list, tabsystem):
        self.db = db
        self.credentials_list = credentials_list
        self.tabsystem = tabsystem

        site_label = ttk.Label(tab, text="Title")
        site_label.grid(row=0, column=0, padx=5)
        self.site_textbox = ttk.Entry(tab)
        self.site_textbox.grid(row=0, column=1, pady=5)

        login_label = ttk.Label(tab, text="Login")
        login_label.grid(row=1, column=0, padx=5)
        self.login_textbox = ttk.Entry(tab)
        self.login_textbox.grid(row=1, column=1, pady=5)

        password_label = ttk.Label(tab, text="Password")
        password_label.grid(row=2, column=0, padx=5)
        self.password_textbox = ttk.Entry(tab, show="*")
        self.password_textbox.grid(row=2, column=1, pady=5)

        button = ttk.Button(tab, text="Add")
        button.grid(row=3, column=1, padx=5)
        button.bind("<Button-1>", self.on_click)

    def on_click(self, event):
        with Session(self.db) as session:
            site = Site(name=self.site_textbox.get())
            cred = Credential(
                login=self.login_textbox.get(),
                password=self.password_textbox.get(),
                site=site,
            )

            session.add_all([
                site,
                cred
            ])

            session.commit()
            print("Added to database.")

            self.credentials_list.load_credentials_to_tree()
            self.tabsystem.select(0)


class CredentialsList:
    def __init__(self, tab, root_window, db, tabsystem):
        self.root_window = root_window
        self.db = db
        self.tabsystem = tabsystem
        self.tree = ttk.Treeview(tab, columns=("Title", "Login"), show="headings", height=10)
        self.load_credentials_to_tree()
        self.configure_tree()
        self.tree.bind("<<TreeviewSelect>>", self.on_click)

    def on_click(self, event):
        item = self.tree.selection()[0]
        selection = self.tree.item(item, "values")
        print(selection)

    def load_credentials_to_tree(self):
        with Session(self.db) as session:
            for credential in session.query(Credential).all():
                self.tree.insert("", "end", values=(credential.site.name, credential.login))

    def configure_tree(self):
        self.tree.column("#1", anchor=tk.CENTER, stretch=tk.NO, width=200)
        self.tree.heading("#1", text="Title")
        self.tree.column("#2", anchor=tk.CENTER, stretch=tk.NO, width=150)
        self.tree.heading("#2", text="Login")
        self.tree.pack()


root = tk.Tk()
root.title("Password Manager")
root.resizable(False, False)
root_width = 450
root_height = 355
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x_offset = int(screen_width / 2 - root_width / 2)
y_offset = int(screen_height / 2 - root_height / 2)
root.geometry(f"{root_width}x{root_height}+{x_offset}+{y_offset}")

tabsystem = ttk.Notebook(root)
credentials_tab = tk.Frame(tabsystem)
add_credentials_tab = tk.Frame(tabsystem)

tabsystem.add(credentials_tab, text="Credentials")
tabsystem.add(add_credentials_tab, text="Add new")
tabsystem.pack(expand=1, fill="both")

engine = create_engine("sqlite:///database.db", echo=False, future=True)
credentials_list = CredentialsList(credentials_tab, root, engine, tabsystem)
add_password = AddPassword(add_credentials_tab, engine, credentials_list, tabsystem)

if len(sys.argv) > 1 and sys.argv[1] == "install":
    install(engine)
    print("Database with tables has been created successfully.")
    quit()

root.mainloop()
