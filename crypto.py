"""This module encrypts and decrypts passwords stored in the database"""

import hashlib
from cryptography.fernet import Fernet
from base64 import b64encode


class Crypto:
    def __init__(self, pin: str):
        pin = Crypto.prepare_pin(pin)
        self.fernet = Fernet(pin)

    @staticmethod
    def prepare_pin(pin):
        """
        Generates a pin (key) to encrypt and decrypt password.
        If lost, you will no longer be able to decrypt the password!

        Args:
            pin (str): string to generate a token

        Returns:
            token: key to encrypt and decrypt password
        """
        token = hashlib.md5(pin.encode("utf-8")).hexdigest()
        token = b64encode(token.encode("utf-8"))
        return token

    def encrypt(self, string):
        """
        Encrypts password.

        Args:
            string: password to encrypt

        Returns:
            encrypted password
        """
        return self.fernet.encrypt(string.encode("utf-8"))

    def decrypt(self, string):
        """
        Decrypts password.

        Args:
            string: password to decrypt

        Returns:
            decrypted password
        """
        return self.fernet.decrypt(string).decode("utf-8")
