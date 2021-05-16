from flask import render_template, url_for, flash, redirect, flash, request, Response, send_from_directory
from flaskblog import app, db, bcrypt
from flaskblog.models import User, Files
from flaskblog.forms import RegistrationForm, LoginForm, UpdateAccountCredsForm, UploadForm, FileOptionsForm
from flask_login import login_user, current_user, logout_user, login_required
import os
from flaskblog import app_utils
from time import sleep
from datetime import datetime
import magic

temp_file = None

@app.route("/", methods=['GET', 'POST'])
@app.route("/home", methods=['GET', 'POST'])
def home():
    form = FileOptionsForm()
    if form.validate_on_submit():
        if request.form.get('submit_download') == 'Enter':
            # Pass the users' entered password and the filename that is
            # passed using an additional field. [[ form.helper_field.data is filename ]]
            decrypted_file = app_utils.file_decryption(form.helper_field.data, form.input_field.data)
            # TODO SEE WHY WHEN STREAMED THE FILE CORRUPTS BUT IS SAVED WELL POSSIBLY CHUNK PROBLEM
            #TODO GET BETTER MIME FUNCTION
            # chunk_size=512
            # chunks = [decrypted_file[i:i+chunk_size] for i in range(0, len(decrypted_file), chunk_size)]
            # mime = magic.Magic(mime=True)
            # file_mimetype = mime.from_file(app.config['TEMPO_STORAGE'] + form.helper_field.data) # 'application/pdf'
            # file_mimetype = app_utils.mime_content_type(form.helper_field.data)
            # return Response(app_utils.generate_file_chunks(chunks), mimetype=file_mimetype)
            print(os.path.realpath(__file__))
            return send_from_directory(directory="../" + app.config['UPLOAD_FOLDER'], filename=form.helper_field.data)
        elif request.form.get('submit_share') == 'Submit':
            print('Share')
        elif request.form.get('submit_delete') == 'Confirm':
            print('Delete')
        else:
            print('Invalid')
    # print(form.errors)

    if current_user.is_authenticated:
        users = User.query.filter_by(username=current_user.username).first()
        files = Files.query.filter_by(owner=users).order_by(Files.date_modified.desc())
        return render_template('home.html', title='My Files', files=files, form=form)

    return render_template('home.html', title='Home', form=form)

@app.route("/upload", methods=['GET', 'POST'])
@login_required
def upload():
    global temp_file
    form = RegistrationForm()
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file:
            temp_file = app_utils.check_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], temp_file))
            return render_template('upload.html', title='Upload', form=form, password_request="True")
    return render_template('upload.html', title='Upload', form=form, password_request="False")

@app.route("/uploadendpoint", methods=['GET', 'POST'])
@login_required
def uploadendpoint():
    global temp_file
    # Get the relevant form
    form = UploadForm()
    # When submited
    if form.validate_on_submit():
        # hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # app_utils.file_encryption(temp_file, hashed_password)
        app_utils.file_encryption(temp_file, form.password.data)
        # Remove temp file after encryption is done and the real final file is stored
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], temp_file))
        temp_file = current_user.username + temp_file
        new_file = Files(filename=str(temp_file), shares='admin', owner=current_user)
        db.session.add(new_file)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('upload.html', title='Upload', form=form, password_request="True")

@app.route("/shares")
@login_required
def shares():
    files = Files.query.all()
    return render_template('shares.html', form=UploadForm())

@app.route("/about")
def about():
    return render_template('about.html', title='About')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()

    # Validate user and login
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            # Previous page the user was trying to access requiring login
            prev_page = request.args.get('next')
            return redirect(prev_page) if prev_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        created_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(created_user)
        db.session.commit()
        flash(f'Account created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountCredsForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated successfully', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account', form=form)

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html', title='Manage')
