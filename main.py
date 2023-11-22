import sys
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from sqlalchemy import create_engine
from install import install


@dataclass
class Credential:
    title: str
    login: str


class CredentialsList:
    def __init__(self, tab, root_window, tabsystem):
        self.root_window = root_window
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
        for credential in credentials:
            self.tree.insert("", "end", values=(credential.title, credential.login))

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

credentials = [
    Credential("credential1", "login1"),
    Credential("credential2", "login2"),
    Credential("credential3", "login3"),
]

credentials_list = CredentialsList(credentials_tab, root, tabsystem)
engine = create_engine("sqlite:///database.db", echo=False, future=True)

if len(sys.argv) > 1 and sys.argv[1] == "install":
    install(engine)
    print("Database with tables has been created successfully.")
    quit()

root.mainloop()
