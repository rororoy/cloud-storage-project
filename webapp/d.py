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

with open('encrypted_file', 'rb') as e:
    encrypted_file = e.read()

decrypted_file = cipher.decrypt(encrypted_file)


with open('decrypted.png', 'wb') as f:
    f.write(decrypted_file.rstrip(b'0'))
