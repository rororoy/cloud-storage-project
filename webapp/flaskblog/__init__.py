from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_dropzone import Dropzone

app = Flask(__name__)
app.config['SECRET_KEY'] = 'aa272ee903e02dc02d9db14de952195d'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = '../server/temp/'
app.config['TEMPO_STORAGE'] = '../server/files/'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
dropzone = Dropzone(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

from flaskblog import routes
