from Crypto.Cipher import AES
from flaskblog import app
import hashlib 
from werkzeug.utils import secure_filename
import os.path
import os
def check_filename(filename):
    filename = secure_filename(filename)
    file_addition = ''
    counter = 0
    while os.path.isfile('../server/temp/' + filename.split('.')[0] + file_addition + '.' + filename.split('.')[1]):
        counter += 1
        file_addition = '(' + str(counter) + ')'
    return filename.split('.')[0] + file_addition + '.' +  filename.split('.')[1]

def pad_file(file):
    while len(file) % 16 != 0:
        file = file + b'0'
    return file

def file_encryption(filename, password):

	password = "password".encode()
	key = hashlib.sha256(password).digest()
	mode = AES.MODE_CBC
	IV = 'This is an IV016'.encode("utf8")
	cipher = AES.new(key, mode, IV)
	
	with open(app.config['UPLOAD_FOLDER'] + filename, 'rb') as f:
		original_file = f.read()

	padded_file = pad_file(original_file)

	encrypted_file = cipher.encrypt(padded_file) 

	with open(app.config['TEMPO_STORAGE'] + filename, 'wb') as e:
		e.write(encrypted_file)	
