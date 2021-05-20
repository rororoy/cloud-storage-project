from flaskblog import db, login_manager
from datetime import datetime
from flask_login import UserMixin

shares = db.Table('shares',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('file_id', db.Integer, db.ForeignKey('files.id'))
)

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
    files_shared = db.relationship('Files', secondary=shares, backref=db.backref('file_viewers', lazy='dynamic'))

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.password}', '{self.role}', '{self.files}')"

class Files(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(40), unique=False, nullable=False)
    actual_filename = db.Column(db.String(40), unique=True, nullable=False)
    date_modified = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # One to many: a file <-- user (used to encompass all of one user's files)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Many to many: a user to a multiple files ---> a file to multiple users
    # REMEMBER THERE IS A FILE_VIEWERS FIELD HERE

    def __repr__(self):
        return f"Files('{self.filename}', '{self.owner_id}', '{self.date_modified}')"
