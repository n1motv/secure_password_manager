from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
import os

class SecurePasswordManager:
    def __init__(self):
        self.encryption_key = None
        self.credentials_file = None
        self.credentials_dict = {}

    def _derive_key(self, master_password, salt):
        return pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)

    def generate_key(self, file_path, master_password):
        try:
            salt = os.urandom(16)
            self.encryption_key = self._derive_key(master_password, salt)
            with open(file_path, "wb") as key_file:
                key_file.write(salt + self.encryption_key)
            print("Key generated and saved successfully.")
        except Exception as e:
            print(f"An error occurred while generating the key: {e}")

    def read_key(self, file_path, master_password):
        try:
            with open(file_path, "rb") as key_file:
                salt = key_file.read(16)
                stored_encryption_key = key_file.read()
            derived_key = self._derive_key(master_password, salt)
            if derived_key == stored_encryption_key:
                self.encryption_key = derived_key
                print("Key read successfully.")
            else:
                print("Incorrect master password.")
        except FileNotFoundError:
            print("The key file does not exist.")
        except Exception as e:
            print(f"An error occurred while reading the key: {e}")

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
                    self.credentials_dict[site] = Fernet(self.encryption_key).decrypt(encrypted_password.encode()).decode()
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

    running = True
    while running:
        option = input("Enter your choice: ")
        if option == "1":
            path = input("Enter the path to save the key: ")
            master_password = input("Enter a master password: ")
            manager.generate_key(path, master_password)
        elif option == "2":
            path = input("Enter the path to the key file: ")
            master_password = input("Enter the master password: ")
            manager.read_key(path, master_password)
                elif option == "3":
            path = input("Enter the path to the password file: ")
            manager.initialize_password_file(path)
        elif option == "4":
            path = input("Enter the path to the password file: ")
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
        elif option == "q":
            running = False
            print("Thank you!")
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
