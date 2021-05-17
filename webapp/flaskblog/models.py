from flaskblog import db, login_manager
from datetime import datetime
from flask_login import UserMixin

# Get a user from the db by id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(5), nullable=False, default='user')
    files = db.relationship('Files', backref='owner', lazy=True)
    shares = db.relationship('Files', backref='shared')

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.password}', '{self.role}', '{self.files}')"

class Files(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(40), unique=True, nullable=False)
    shares = db.Column(db.String(40), unique=False, nullable=False)
    date_modified = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # One to many: a file <-- user (used to encompass all of one user's files)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Many to many: a user to a multiple files ---> a file to multiple users
    share_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Files('{self.filename}', '{self.shares}', '{self.owner_id}', '{self.date_modified}')"
