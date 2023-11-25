# Password Manager
I'm writing this application in order to improve my programming skills.\
It uses [Tkinter](https://docs.python.org/3/library/tkinter.html) for GUI, [SQLite](https://www.sqlite.org) database, [SQL Alchemy](https://www.sqlalchemy.org/) as ORM and [Cryptography](https://cryptography.io) library for password encryption and decryption.

### Description
This application stores your credentials in the form of a title, login, and password.\
These can be credentials for other applications, games, websites, social media, etc.\
The application is secured by main password You create during install.\
your passwords are not visible from the user interface. They are stored in the database as encrypted!

### Install
Just type `python main.py install` and a database with all necessary tables will be created.\
Next, You will be asked to enter your new main password.\
This password has also been saved in the database.

### Use
* After login, You may add a new credential on "Add new" tab.
* Enter the title, login and password, and then click the "Add" button.
* Your credential will be added to the database and You will be switched to the "Credentials" tab.
* If You want to use the saved password, click on the row with the corresponding credentials on the "Credentials" tab, and the password will be loaded from the database, decrypted, and copied to the clipboard for immediate use.
* Your password is now in the clipboard, ready to be pasted in the appropriate place!
