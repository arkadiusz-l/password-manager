# Password Manager
I'm writing this application in order to improve my programming skills.\
It uses [Tkinter](https://docs.python.org/3/library/tkinter.html) for GUI, [SQLite](https://www.sqlite.org) database, [SQL Alchemy](https://www.sqlalchemy.org/) as ORM and [Cryptography](https://cryptography.io) library for password encryption and decryption.

## Description
This application stores your credentials in the form of a title, login, and password.\
These can be credentials for other applications, games, websites, social media, etc.\
The application is secured by master password You create during install.\
Your passwords are not visible from the user interface. They are stored in the database as encrypted!

## Key features
* One master password for all your credentials.
* Storing your passwords encrypted.
* Generating a random, complex password that is difficult to crack or guess.
* Prevent adding password that:
  - is the same as the login,
  - is same as the title,
  - not meets complexity requirements.
* Allowing to force adding passwords that not meet complexity requirements (if you already have such a password in some website/service/application, etc.)
  
## Installation
Clone the repo or download the [latest release](https://github.com/arkadiusz-l/password-manager/releases/latest) and type:
```
python main.py install
```
The database with all necessary tables will be created.\
Next, You will be asked to enter your new master password.\
This master password has also been saved in the database.

## Usage
* REMEMBER your master password, because without it, You won't be able to access the application and won't have access to your credentials!
* After login, You may add a new credential on "Add new" tab.
* Enter the title, login and password, and then click the "Add" button.
* Your credential will be added to the database and You will be switched to the "Credentials" tab.
* If You want to use the saved password, click on the row with the corresponding credentials on the "Credentials" tab, and the password will be loaded from the database, decrypted, and copied to the clipboard for immediate use.
* Your password is now in the clipboard, ready to be pasted in the appropriate place!
* To edit or delete a credential, left-click on it to select, then right-click and choose the appropriate option from the menu.

## Clarification
During development, I decided to change the commit messages to be consistent with Conventional Commits and Semantic Commits Messages.
The older commit messages look different.

More info:
- https://www.conventionalcommits.org
- https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716
- https://cbea.ms/git-commit

## Project Status
In progress...
