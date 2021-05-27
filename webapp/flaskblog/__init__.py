from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_dropzone import Dropzone
from flaskblog.config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
dropzone = Dropzone()
login_manager = LoginManager()

login_manager.login_view = 'users.login'
login_manager.login_message_category = 'info'

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    bcrypt.init_app(app)
    dropzone.init_app(app)
    login_manager.init_app(app)

    from flaskblog.users.routes import users
    from flaskblog.files.routes import files
    from flaskblog.main.routes import main
    app.register_blueprint(users)
    app.register_blueprint(files)
    app.register_blueprint(main)

    return app
