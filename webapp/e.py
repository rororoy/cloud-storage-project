from Crypto.Cipher import AES
import hashlib 

def pad_file(file):
    while len(file) % 16 != 0:
        file = file + b'0'
    return file

password = "password".encode()
key = hashlib.sha256(password).digest()
mode = AES.MODE_CBC

IV = 'This is an IV016'

cipher = AES.new(key, mode, IV)

with open('secret.png', 'rb') as f:
    original_file = f.read()

padded_file = pad_file(original_file)

encrypted_message = cipher.encrypt(padded_file) 

print(encrypted_message)

with open('encrypted_file', 'wb') as e:
    e.write(encrypted_message)
