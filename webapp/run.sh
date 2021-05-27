# App env vars
export SECRET_KEY="aa272ee903e02dc02d9db14de952195d"
export SQLALCHEMY_DATABASE_URI="sqlite:///site.db"
export UPLOAD_FOLDER="../server/temp/"
export TEMPO_STORAGE="../server/files/"

# Start the app
python3 run.py
