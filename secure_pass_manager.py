from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import pyperclip


def _derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


class SecurePasswordManager:
    def __init__(self):
        self.encryption_key = None
        self.credentials_file = None
        self.credentials_dict = {}

    def generate_key(self, file_path, master_password):
        try:
            self.encryption_key = Fernet.generate_key()
            salt = os.urandom(16)
            derived_key = _derive_key(master_password, salt)
            fernet = Fernet(derived_key)
            encrypted_key = fernet.encrypt(self.encryption_key)
            with open(file_path, "wb") as key_file:
                key_file.write(salt + encrypted_key)
            print("Key generated and saved successfully.")
            return True
        except Exception as e:
            print(f"An error occurred while generating the key: {e}")
            return False

    def read_key(self, file_path, master_password):
        try:
            with open(file_path, "rb") as key_file:
                data = key_file.read()
            salt, encrypted_key = data[:16], data[16:]
            derived_key = _derive_key(master_password, salt)
            fernet = Fernet(derived_key)
            self.encryption_key = fernet.decrypt(encrypted_key)
            print("Key read successfully.")
            return True
        except FileNotFoundError:
            print("The key file does not exist.")
            return False
        except Exception as e:
            print(f"An error occurred while reading the key: {e}")
            return False

    def initialize_password_file(self, file_path, initial_data=None):
        try:
            self.credentials_file = file_path
            if initial_data is not None:
                for site, password in initial_data.items():
                    self.store_password(site, password)
            print("Password file initialized successfully.")
        except Exception as e:
            print(f"An error occurred while initializing the password file: {e}")

    def read_password_file(self, file_path):
        try:
            self.credentials_file = file_path
            with open(file_path, "r") as file:
                for line in file:
                    site, encrypted_password = line.strip().split(":")
                    self.credentials_dict[site] = Fernet(self.encryption_key).decrypt(
                        encrypted_password.encode()).decode()
            print("Password file read successfully.")
        except FileNotFoundError:
            print("The password file does not exist.")
        except Exception as e:
            print(f"An error occurred while reading the password file: {e}")

    def store_password(self, site, password):
        try:
            self.credentials_dict[site] = password
            if self.credentials_file is not None:
                with open(self.credentials_file, "a+") as file:
                    encrypted_password = Fernet(self.encryption_key).encrypt(password.encode())
                    file.write(site + ":" + encrypted_password.decode() + "\n")
            print(f"Password for {site} stored successfully.")
        except Exception as e:
            print(f"An error occurred while storing the password: {e}")

    def retrieve_password(self, site):
        try:
            return self.credentials_dict[site]
        except KeyError:
            print(f"No password found for site: {site}")
        except Exception as e:
            print(f"An error occurred while retrieving the password: {e}")


def main():
    manager = SecurePasswordManager()

    print("""What do you want to do?
    (1) Generate a new key 
    (2) Read an existing key
    (3) Initialize a new password file
    (4) Read an existing password file
    (5) Store a new password
    (6) Retrieve a password
    (q) Exit program
    """)

    running = False
    while not running:
        option = input("Enter your choice: ")
        if option == "1":
            path = input("Enter the path: ")
            master_password = input("Enter master password: ")
            manager.generate_key(path, master_password)
        elif option == "2":
            path = input("Enter the path: ")
            master_password = input("Enter master password: ")
            manager.read_key(path, master_password)
        elif option == "3":
            path = input("Enter the path: ")
            manager.initialize_password_file(path)
        elif option == "4":
            path = input("Enter the path: ")
            manager.read_password_file(path)
        elif option == "5":
            site = input("Enter the site: ")
            password = input("Enter the password: ")
            manager.store_password(site, password)
        elif option == "6":
            site = input("What site do you want to retrieve? ")
            password = manager.retrieve_password(site)
            if password:
                print(f"Password for {site} is {password}")
                answer = input("Do you want to copy it to the clipboard ? (y/n)")
                if answer == "y":
                    pyperclip.copy(password)
        elif option == "q":
            running = True
            print("Thank you!")
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
