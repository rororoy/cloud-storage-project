import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER')
    TEMPO_STORAGE = os.environ.get('TEMPO_STORAGE')
