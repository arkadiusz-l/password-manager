import re
import sys
import tkinter as tk
from tkinter import ttk
from _tkinter import TclError
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
    """Represents login window"""

    def __init__(self, window, db):
        """
        Args:
            window: window to place widgets
            db: database
        """
        self.db = db
        self.window = window
        self.master_password_label = ttk.Label(self.window, text="Enter master password:")
        self.master_password_label.place(relx=0.5, rely=0.3, anchor=tk.CENTER)
        self.master_password_textbox = ttk.Entry(self.window, show="*")
        self.master_password_textbox.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        self.master_password_button = ttk.Button(self.window, text="Log In")
        self.master_password_button.bind("<Button-1>", self.on_click_log_in)
        self.master_password_button.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.message = tk.StringVar()
        self.message_label = ttk.Label(
            self.window, textvariable=self.message, font=("Segoe UI", 9, "bold"),
            foreground="#f02626"
        )
        self.message_label.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
        self.user_password = ""
        self.tab = None

    @staticmethod
    def calculate_password_hash(password):
        """
        Calculates a given master password hash for later login.

        Args:
            password: the password, whose hash will be calculated

        Returns:
            password hash: calculated master password hash
        """
        password = password.encode("utf-8")
        password_hash = sha1(password).hexdigest()
        return password_hash

    def check_master_password(self, password):
        """
        Checks if the given password hash matches the stored master password hash.

        Args:
            password: the password to be checked

        Returns:
            bool: True if the given password hash matches the stored master password hash, False otherwise
        """
        password_hash = self.calculate_password_hash(password)
        with Session(self.db) as session:
            user_model = session.get(UserModel, 1)
            password_hash_from_db = user_model.master_password

        return password_hash_from_db == password_hash

    def on_click_log_in(self, event):
        """
        Handles the click event of the `Log In` button

        Args:
            event: click event

        Side Effects:
            Sets the message attribute to indicate password incorrect
        """
        self.user_password = self.master_password_textbox.get()
        password_correct = self.check_master_password(self.user_password)
        if password_correct:
            self.tab = Tab()
            self.tab.show_tabs()

        self.message.set("Password incorrect!")


class Tab:
    """Represents view of the tabs after user login"""

    def __init__(self):
        self.tabsystem = ttk.Notebook(root)
        self.credentials_tab = ttk.Frame(self.tabsystem)
        self.credentials_list = CredentialsList(self.credentials_tab, root, db_engine, log_in.user_password, self.tabsystem)
        self.add_credential_tab = ttk.Frame(self.tabsystem)
        self.add_credential = AddCredential(self.add_credential_tab, db_engine, self.credentials_list, self.tabsystem, log_in.user_password)

    def show_tabs(self):
        """
        Shows tabs after user login
        """
        self.tabsystem.add(self.credentials_tab, text="Credentials")
        self.tabsystem.add(self.add_credential_tab, text="Add")
        self.tabsystem.pack()
        self.destroy_login_widgets()

    @staticmethod
    def destroy_login_widgets():
        """
        Destroys login widgets after user login
        """
        log_in.master_password_label.destroy()
        log_in.master_password_textbox.destroy()
        log_in.master_password_button.destroy()
        log_in.message_label.destroy()


class AddCredential:
    """Represents a form for credential adding"""

    def __init__(self, tab, db, credentials_list, tabsystem, master_password):
        """
        Args:
            tab: tab to place widgets
            db: database
            credentials_list: tab with list of credentials
            tabsystem: widget manages a collection of tabs
            master_password: user master password
        """
        self.tab = tab
        self.db = db
        self.credentials_list = credentials_list
        self.tabsystem = tabsystem
        self.crypto = Crypto(master_password)

        title_label = ttk.Label(self.tab, text="Title:")
        title_label.place(relx=0.0, rely=0.1, x=100, anchor=tk.E)
        self.title_textbox = ttk.Entry(self.tab)
        self.title_textbox.place(relx=0.0, rely=0.1, x=115, anchor=tk.W, width=200)

        username_label = ttk.Label(self.tab, text="Username:")
        username_label.place(relx=0.0, rely=0.2, x=100, anchor=tk.E)
        self.username_textbox = ttk.Entry(self.tab)
        self.username_textbox.place(relx=0.0, rely=0.2, x=115, anchor=tk.W, width=200)

        password_label = ttk.Label(self.tab, text="Password:")
        password_label.place(relx=0.0, rely=0.3, x=100, anchor=tk.E)
        self.password_textbox = ttk.Entry(self.tab, show="*")
        self.password_textbox.place(relx=0.0, rely=0.3, x=115, anchor=tk.W, width=200)

        generate_button = ttk.Button(self.tab, text="Generate")
        generate_button.place(relx=0.0, rely=0.3, x=325, anchor=tk.W)
        generate_button.bind("<Button-1>", self.on_click_generate)

        clear_button = ttk.Button(self.tab, text="Clear", width=6, command=self.clear_tab)
        clear_button.place(relx=0.0, rely=0.4, x=100, anchor=tk.E)

        add_button = ttk.Button(self.tab, text="Add")
        add_button.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        add_button.bind("<Button-1>", self.on_click_add_credential)

        self.message = tk.StringVar()
        self.message_label = ttk.Label(
            self.tab, textvariable=self.message, font=("Segoe UI", 9, "bold"),
            foreground="#f02626"
        )
        self.message_label.place(relx=0.5, rely=0.45, anchor=tk.N)

        self.force_add_boolvar = tk.BooleanVar(master=self.tab, value=False)
        self.force_add_checkbox = ttk.Checkbutton(self.tab, text="Add it anyway", variable=self.force_add_boolvar)

        self.title = ""
        self.username = ""
        self.password = ""
        self.edit = False

    def on_click_add_credential(self, event):
        """
        Handles the click event of the `Add` button.
        Saves new or edited credentials to the database.

        Args:
            event: click event
        """
        self.title = self.title_textbox.get()
        self.username = self.username_textbox.get()
        self.password = self.password_textbox.get()

        is_fields_are_empty = self.check_empty_fields(self.title, self.username, self.password)
        if is_fields_are_empty:
            return

        if not self.edit:
            is_exists = self.check_if_exists(self.title, self.username)
            if is_exists:
                return

        is_password_same_as_title = self.check_password_vs_title(self.password, self.title)
        if is_password_same_as_title:
            return

        is_password_same_as_username = self.check_password_vs_username(self.password, self.username)
        if is_password_same_as_username:
            return

        is_password_complex = self.check_password_complexity(self.password)
        if not is_password_complex:
            self.force_add_checkbox.place(relx=0.5, rely=0.75, anchor=tk.CENTER)
            force_add_checked = self.force_add_boolvar.get()
            if not force_add_checked:
                return

        if self.edit:
            selected = self.credentials_list.tree.selection()[0]
            self.edit_in_database(self.db, selected, self.title, self.username, self.password)
        elif not self.edit:
            self.save_to_database(self.db, self.password)

        self.tabsystem.select(0)
        self.credentials_list.load_credentials_to_tree()
        self.clear_tab()
        self.edit = False

    def edit_in_database(self, db, item, new_title, new_username, new_password):
        """
        Saves edited credential to the database.

        Args:
            db: database
            item: selected credential
            new_title: new title of credential to save
            new_username: new username to save
            new_password: new password to save
        """
        selected = self.credentials_list.tree.item(item, "values")
        title = selected[0]
        username = selected[1]
        with Session(db) as session:
            credential = session.query(CredentialModel).filter(
                CredentialModel.title == title,
                CredentialModel.username == username,
                ).one()
            decrypted_password = self.crypto.decrypt(credential.password)
            if credential.title != new_title:
                credential.title = new_title
            if credential.username != new_username:
                credential.username = new_username
            if decrypted_password != new_password:
                new_password = self.crypto.encrypt(new_password)
                credential.password = new_password
            session.commit()

    def save_to_database(self, db, password):
        """
        Saves new credential to the database.

        Args:
            db: database
            password: password to save
        """
        password = self.crypto.encrypt(password)
        credential = CredentialModel(title=self.title, username=self.username, password=password)
        with Session(db) as session:
            session.add(credential)
            session.commit()

    def check_empty_fields(self, title, username, password):
        """
        Checks if the fields in the form for adding or editing a credential are empty.

        Args:
            title: the title textbox value
            username: the username textbox value
            password: the password textbox value

        Returns:
            bool: True if any field is empty, False otherwise

        Side Effects:
            Sets a message attribute to indicate that all fields must be completed
        """
        if title == "" or username == "" or password == "":
            self.message.set("Please complete all fields")
            return True

    def check_if_exists(self, title, username):
        """
        Checks if given a pair of title and username already exists.

        Args:
            title: the title textbox value
            username: the username textbox value

        Returns:
            bool: True if given a pair of title and username already exists, False otherwise

        Side Effects:
            Sets the message attribute to indicate they already exists
        """
        try:
            self.credentials_list.get_credential_from_db(title, username)
            self.message.set("The given pair of title + username already exists!")
            return True
        except NoResultFound:
            return False

    def check_password_vs_title(self, password, title):
        """
        Checks if given password is the same as given title.

        Args:
            password: the password to be checked
            title: the title to be compared with

        Returns:
            True if given password as the same as given title, False otherwise

        Side Effects:
            Sets the message attribute to indicate they are the same
        """
        if password == title:
            self.message.set("The password should not be the same as title!")
            return True
        return False

    def check_password_vs_username(self, password, username):
        """
        Checks if given password is same as given username.

        Args:
            password: the password to be checked
            username: the username to be compared with

        Returns:
            True if given password as the same as given username, False otherwise

        Side Effects:
            Sets the message attribute to indicate they are the same
        """
        if password == username:
            self.message.set("The password should not be the same as the username!")
            return True
        return False

    def check_password_complexity(self, password):
        """
        Checks the complexity of given password.

        Args:
            password (str): the password to be checked

        Returns:
            bool: True if the password meets the complexity requirements, False otherwise

        Side Effects:
            Sets the message attribute to indicate the missing complexity requirements

        Complexity Requirements:
            - the password must have at least 8 characters
            - the password must have at least 1 uppercase letter
            - the password must have at least 1 lowercase letter
            - the password must have at least 1 digit
            - the password must have at least 1 special character
        """
        is_complex = True
        message = "The password must have at least:"
        if len(password) < 8:
            message += "\n8 characters!"
            self.message.set(message)
            is_complex = False
        if not re.search(r"[A-Z]", password):
            message += "\n1 uppercase letter!"
            self.message.set(message)
            is_complex = False
        if not re.search(r"[a-z]", password):
            message += "\n1 lowercase letter!"
            self.message.set(message)
            is_complex = False
        if not re.search(r"\d", password):
            message += "\n1 digit!"
            self.message.set(message)
            is_complex = False
        if not re.search(r"[!\"#$%&\'()*+,-./:;<=>?@\[\]\\^_`{|}~]", password):
            message += "\n1 special character!"
            self.message.set(message)
            is_complex = False

        return is_complex

    def generate_password(self, letters, digits, specials):
        """
        Generates a random password based on the specified parameters.

        Args:
            letters: the number of letters to include in the password
            digits: the number of digits to include in the password
            specials: the number of special characters to include in the password

        Returns:
            password: a randomly generated password

        Password generation:
            - randomly selects digits from 0 to 9 to include in the password
            - randomly selects letters (both uppercase and lowercase) to include in the password
            - randomly selects special characters to include in the password
            - shuffles the characters to create a random order
            - joins the shuffled characters to create the final password

        Example:
            password = generate_password(5, 2, 1)
            # Possible output: "xHBo!3c9"
        """
        all_letters = ascii_letters
        all_digits = "".join(map(str, range(0, 10)))
        all_special_characters = punctuation
        self.password = choices(population=all_digits, k=digits)
        self.password += choices(population=all_letters, k=letters)
        self.password += choices(population=all_special_characters, k=specials)
        shuffle(self.password)
        self.password = "".join(self.password)
        return self.password

    def on_click_generate(self, event):
        """
        Handles a click event of the `Generate` button.
        Generates a random password until it meets the complexity requirements
        and updates the password textbox with it.

        Args:
            event: click event
        """
        is_password_complex = False
        while not is_password_complex:
            self.password = self.generate_password(letters=5, digits=2, specials=1)
            is_password_complex = self.check_password_complexity(self.password)
            self.message.set("")
        self.password_textbox.delete(0, tk.END)
        self.password_textbox.insert(0, self.password)

    def clear_tab(self):
        """
        Clears textboxes, messages and checkbox on the `Add` tab.
        """
        self.title_textbox.delete(0, tk.END)
        self.username_textbox.delete(0, tk.END)
        self.password_textbox.delete(0, tk.END)
        self.message.set("")
        self.force_add_checkbox.place_forget()
        self.edit = False


class CredentialsList:
    """Represents credentials list on a `Credentials` tab"""

    def __init__(self, tab, root_window, db, master_password, tabsystem):
        """
        Args:
            tab: tab to place widgets
            root_window: root window
            db: database
            master_password: user master password
            tabsystem: widget manages a collection of tabs
        """
        self.root_window = root_window
        self.db = db
        self.tabsystem = tabsystem
        self.tree = ttk.Treeview(tab, columns=("Title", "Username"), show="headings", height=16)
        self.configure_tree(tab)
        self.context_menu = tk.Menu(tab, tearoff=0)
        self.configure_context_menu()
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.crypto = Crypto(master_password)
        self.load_credentials_to_tree()
        self.selected = None

    def configure_context_menu(self):
        """
        Configures a context menu that appears when right-click in the credentials list
        """
        self.context_menu.add_command(label="Edit")
        self.context_menu.add_command(label="Delete")

    def show_context_menu(self, event):
        """
        Shows a context menu after right-click in the credentials list and triggers actions on it.

        Args:
            event: click event
        """
        self.context_menu.post(event.x_root, event.y_root)
        self.context_menu.entryconfigure("Edit", command=lambda: self.edit_credential(self.selected))
        self.context_menu.entryconfigure("Delete", command=lambda: self.delete_credential(self.selected))

    def edit_credential(self, item):
        """
        Loads credential into textboxes on the `Add` tab for editing.

        Args:
            item: selected credential
        """
        try:
            credential = self.get_selected_credential()
        except IndexError:
            return
        decrypted_password = self.crypto.decrypt(credential.password)
        log_in.tab.add_credential.clear_tab()
        log_in.tab.add_credential.title_textbox.insert(0, credential.title)
        log_in.tab.add_credential.username_textbox.insert(0, credential.username)
        log_in.tab.add_credential.password_textbox.insert(0, decrypted_password)
        log_in.tab.add_credential.edit = True
        self.tabsystem.select(1)

    def delete_credential(self, item):
        """
        Deletes the selected credential from the database.

        Args:
            item: selected credential
        """
        try:
            credential = self.get_selected_credential()
        except (IndexError, TclError):
            return
        with Session(self.db) as session:
            session.delete(credential)
            session.commit()
        self.load_credentials_to_tree()

    def get_credential_from_db(self, title, username):
        """
        Gets credential from the database.

        Args:
            title: title of the credential
            username: username

        Returns:
            The credential matching the given title and username

        Raises:
            NoResultFound: if no credential is found matching the given title and username
            MultipleResultsFound: if multiple credentials are found matching the given title and username
        """
        with Session(self.db) as session:
            return session.query(CredentialModel).filter(
                CredentialModel.title == title,
                CredentialModel.username == username,
                ).one()

    def get_selected_credential(self):
        """
        Gets selected credential.

        Returns:
            The selected credential
        """
        self.selected = self.tree.selection()[0]
        selected = self.tree.item(self.selected, "values")
        title = selected[0]
        username = selected[1]
        credential = self.get_credential_from_db(title, username)
        return credential

    def click_on_selected(self, event):
        """
        Handles the click event of the selected credential.

        Args:
            event: click event
        """
        credential = self.get_selected_credential()
        decrypted = self.crypto.decrypt(credential.password)
        self.root_window.clipboard_clear()
        self.root_window.clipboard_append(decrypted)

    def load_credentials_to_tree(self):
        """
        Loads the credentials from the database to the tree widget on the `Credentials` tab.
        """
        self.tree.delete(*self.tree.get_children())
        with Session(self.db) as session:
            credentials = session.query(CredentialModel).all()
            for credential in credentials:
                self.tree.insert("", "end", values=(credential.title, credential.username))

    def configure_tree(self, tab):
        """
        Configures the tree widget on the `Credentials` tab.

        Args:
            tab: tab to place widget
        """
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.column("#1", anchor=tk.CENTER, stretch=tk.YES, width=225)
        self.tree.heading("#1", text="Title")
        self.tree.column("#2", anchor=tk.CENTER, stretch=tk.YES, width=202)
        self.tree.heading("#2", text="Username")
        self.tree.bind("<<TreeviewSelect>>", self.click_on_selected)
        self.tree.pack()


if __name__ == '__main__':
    def install():
        """
        Creates a database and configures the user master password for the application.
        """
        if len(sys.argv) > 1 and sys.argv[1] == "install":
            create_database(db_engine)
            master_password = input("Enter master password:\n")
            master_password_hash = LogIn.calculate_password_hash(master_password)

            with Session(db_engine) as session:
                user = UserModel(id=1, master_password=master_password_hash)
                session.add(user)
                session.commit()
            print("Master password saved successfully.")
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
