from __future__ import unicode_literals
import os
import base64
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as key_log


def encrypted(key):
    fernet = Fernet(key)
    for i, file in enumerate(xfolder):
            with open(f"{path_folder}\\{file}","rb") as file_key:
                data = file_key.read()
                encrpyted = fernet.encrypt(data)
                with open(f"{path_folder}\\{file}","wb") as f:
                        f.write(encrpyted)

def decrypted(key):
    fernet = Fernet(key)
    for i, file in enumerate(xfolder):
            with open(f"{path_folder}\\{file}","rb") as file_key:
                data = file_key.read()
                decrpyted = fernet.decrypt(data)
                with open(f"{path_folder}\\{file}","wb") as f:
                        f.write(decrpyted)

def Auth(PS_data):
    password_auth = PS_data
    password = password_auth.encode()
    salt = b'\xed[\xcb-F!A\x00\xde\x86%\xa7FK\xc9\x96'
    kdf = key_log(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key
    
if __name__ == "__main__":
    # Path Folder
    path_folder = r""
    xfolder = os.listdir(path_folder)
    # Path file key 
    aut_key = str(input("Enter Password :"))
    key = Auth(aut_key)
    
    # if 'encrypted_key.key' in xfiles:
    #     pass
    # else:
    #     with open(f"{path_file}\\encrypted_key.key","wb") as locker_key:
    #         key = Fernet.generate_key()
    #         locker_key.write(key)
    #     print("kelar")

    # # get key
    # with open(f"{path_file}\\encrypted_key.key","rb") as locker_key:
    #     key = locker_key.read()
    #     locker_key.close()
        
    print("""
    1.encrypted file
    2.decrypted file
    """)
    a = int(input("Masukan pilihan : "))
    try:
        if a == 1:
            encrypted(key)
        elif a == 2:
            decrypted(key)
    except (cryptography.fernet.InvalidToken, TypeError):
        print("the key is wrong")