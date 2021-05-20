from Crypto.Cipher import AES
from flaskblog import app
import hashlib
from werkzeug.utils import secure_filename
import os.path
import os
import hashlib

def check_filename(username, filename):
    # The function returns a name for the file that isnt already used in the temporary storage folder.
    # File name policy: duplicates will have a (1)/(2)/.. appended to them
    filename = secure_filename(filename)
    file_addition = ''
    counter = 0
    hashed_filename = hashlib.md5((username + filename.split('.')[0] + file_addition + '.' + filename.split('.')[1]).encode())
    hashed_filename = str(hashed_filename.hexdigest()) + '.' + filename.split('.')[1]
    true_filename = filename.split('.')[0] + file_addition + '.' + filename.split('.')[1]
    while os.path.isfile(app.config['TEMPO_STORAGE'] + hashed_filename):
        counter += 1
        file_addition = '(' + str(counter) + ')'
        hashed_filename = hashlib.md5((username +  filename.split('.')[0] + file_addition + '.' + filename.split('.')[1]).encode())
        hashed_filename = str(hashed_filename.hexdigest()) + '.' + filename.split('.')[1]
        true_filename = filename.split('.')[0] + file_addition + '.' + filename.split('.')[1]
    return hashed_filename, true_filename

def pad_file(file):
    while len(file) % 16 != 0:
        file = file + b'0'
    return file

def file_encryption(filename, filename_enc, password, username):
    # The function encrypts the uploaded file with AES
    password = password.encode()
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_CBC
    IV = 'This is an IV016'.encode("utf8")
    cipher = AES.new(key, mode, IV)

    with open(app.config['UPLOAD_FOLDER'] + filename_enc, 'rb') as f:
        original_file = f.read()

    padded_file = pad_file(original_file)
    encrypted_file = cipher.encrypt(padded_file)

    with open(app.config['TEMPO_STORAGE'] + filename_enc, 'wb') as e:
        e.write(encrypted_file)

def file_decryption(username, actual_filename, password):
    password = password.encode()
    key = hashlib.sha256(password).digest()
    mode = AES.MODE_CBC
    IV = 'This is an IV016'.encode("utf8")
    cipher = AES.new(key, mode, IV)

    hashed_filename = str(hashlib.md5((actual_filename).encode()).hexdigest())
    hashed_filename = hashed_filename + '.' + actual_filename.split('.')[1]

    with open(app.config['TEMPO_STORAGE'] + hashed_filename, 'rb') as e:
        encrypted_file = e.read()

    with open(app.config['UPLOAD_FOLDER'] + actual_filename.replace(username, ''), 'wb') as f:
        f.write(cipher.decrypt(encrypted_file).rstrip(b'0'))

    return cipher.decrypt(encrypted_file).rstrip(b'0')

def generate_file_chunks(chunks_list):
    for chunk in chunks_list:
        yield chunk.encode()

def mime_content_type(filename):
    """Get mime type
    :param filename: str
    :type filename: str
    :rtype: str
    """
    mime_types = dict(
        txt='text/plain',
        htm='text/html',
        html='text/html',
        php='text/html',
        css='text/css',
        js='application/javascript',
        json='application/json',
        xml='application/xml',
        swf='application/x-shockwave-flash',
        flv='video/x-flv',

        # images
        png='image/png',
        jpe='image/jpeg',
        jpeg='image/jpeg',
        jpg='image/jpeg',
        gif='image/gif',
        bmp='image/bmp',
        ico='image/vnd.microsoft.icon',
        tiff='image/tiff',
        tif='image/tiff',
        svg='image/svg+xml',
        svgz='image/svg+xml',

        # archives
        zip='application/zip',
        rar='application/x-rar-compressed',
        exe='application/x-msdownload',
        msi='application/x-msdownload',
        cab='application/vnd.ms-cab-compressed',

        # audio/video
        mp3='audio/mpeg',
        ogg='audio/ogg',
        qt='video/quicktime',
        mov='video/quicktime',

        # adobe
        pdf='application/pdf',
        psd='image/vnd.adobe.photoshop',
        ai='application/postscript',
        eps='application/postscript',
        ps='application/postscript',

        # ms office
        doc='application/msword',
        rtf='application/rtf',
        xls='application/vnd.ms-excel',
        ppt='application/vnd.ms-powerpoint',

        # open office
        odt='application/vnd.oasis.opendocument.text',
        ods='application/vnd.oasis.opendocument.spreadsheet',
    )

    ext = os.path.splitext(filename)[1][1:].lower()
    if ext in mime_types:
        return mime_types[ext]
    else:
        return 'application/octet-stream'
