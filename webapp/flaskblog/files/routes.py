from flask import (render_template, url_for, flash, current_app,
                   redirect, request, abort, Blueprint, send_from_directory)
from flask_login import current_user, login_required
from flaskblog import db
from flaskblog.models import Files, User
from flaskblog.files.forms import UploadForm, FileOptionsForm, RegistrationForm
import os
from flaskblog import app_utils

files = Blueprint('files', __name__)

temp_file = None
temp_file_enc = None

@files.route("/", methods=['GET', 'POST'])
@files.route("/home", methods=['GET', 'POST'])
def home():
    # dict.session.pop('_flashes', None)
    if str(request.args.get("message")) == 'filedel':
        flash('Your file has been deleted', 'file-deleted')
    elif str(request.args.get("message")) == 'fileshare':
        flash('Your file has been shared', 'file-share')
    form = FileOptionsForm()
    if form.validate_on_submit():
        if request.form.get('submit_download') == 'Enter':
            # Pass the users' entered password and the filename that is
            # passed using an additional field. [[ form.helper_field.data is filename ]]
            decrypted_file = app_utils.file_decryption(current_user.username, current_user.username + form.helper_field.data, form.input_field.data)
            # TODO SEE WHY WHEN STREAMED THE FILE CORRUPTS BUT IS SAVED WELL POSSIBLY CHUNK PROBLEM
            #TODO GET BETTER MIME FUNCTION
            # chunk_size=512
            # chunks = [decrypted_file[i:i+chunk_size] for i in range(0, len(decrypted_file), chunk_size)]
            # mime = magic.Magic(mime=True)
            # file_mimetype = mime.from_file(current_current_app.config['TEMPO_STORAGE'] + form.helper_field.data) # 'application/pdf'
            # file_mimetype = app_utils.mime_content_type(form.helper_field.data)
            # return Response(app_utils.generate_file_chunks(chunks), mimetype=file_mimetype)

            # TODO FILES STAYS IN THE TEMPORARY STORAGE. ACTUALLY STREAMING NEEDS FIXING
            return send_from_directory(directory="../" + current_app.config['UPLOAD_FOLDER'], filename=form.helper_field.data, as_attachment=True)

        # CURRENTLY DISABLED
        elif request.form.get('submit_share') == 'Submit':
            exists = db.session.query(db.exists().where(User.username == form.input_field.data)).scalar()
            if exists:
                # Get requested file
                #users = User.query.filter_by(username=current_user.username).first()
                #requested_file = users.files.filter_by(filename=form.helper_field.data)
                print('ID'+str(current_user.id))
                requested_file = Files.query.filter_by(filename=form.helper_field.data, owner_id=current_user.id).first()
                shared_with_user = User.query.filter_by(username=form.input_field.data).first()
                requested_file.file_viewers.append(shared_with_user)
                db.session.commit()
                #db.session.commit()

                # print(requested_file.filename)
                pass
            else:
                flash('User not found', 'danger')

        elif request.form.get('submit_delete') == 'Confirm':
            print(form.input_field.data, form.helper_field.data)
            if form.helper_field.data == form.input_field.data:
                # Get requested file
                users = User.query.filter_by(username=current_user.username).first()
                requested_file = Files.query.filter_by(filename=form.input_field.data, owner_id=current_user.id).first()

                db.session.delete(requested_file)
                db.session.commit()
                os.remove(os.path.join(current_app.config['TEMPO_STORAGE'], requested_file.actual_filename))
                return redirect(url_for('files.redirection', message="filedel"))
                # flash('Your file has been deleted', 'success')
            else:
                flash('File name does not match', 'danger')

        else:
            print('Invalid')

    if current_user.is_authenticated:
        files = Files.query.filter_by(owner_id=current_user.id).all()
        return render_template('home.html', title='My Files', files=files, form=form)

    return render_template('home.html', title='Home', form=form)

@files.route("/redirection", methods=['GET', 'POST'])
@login_required
def redirection():
    message = str(request.args.get("message"))
    return redirect(url_for('files.home', message=message))

@files.route("/upload", methods=['GET', 'POST'])
@login_required
def upload():
    global temp_file
    global temp_file_enc
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
            temp_file_enc, temp_file = app_utils.check_filename(current_user.username, file.filename)
            # temp_file = file.filename
            file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], temp_file_enc))
            print(os.getcwd())
            return render_template('upload.html', title='Upload', form=form, password_request="True")
    return render_template('upload.html', title='Upload', form=form, password_request="False")

@files.route("/uploadendpoint", methods=['GET', 'POST'])
@login_required
def uploadendpoint():
    global temp_file
    global temp_file_enc
    # Get the relevant form
    form = UploadForm()
    # When submited
    if form.validate_on_submit():
        # hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # app_utils.file_encryption(temp_file, hashed_password)
        app_utils.file_encryption(temp_file, temp_file_enc, form.password.data, current_user.username)
        # Remove temp file after encryption is done and the real final file is stored
        os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'], temp_file_enc))

        new_file = Files(filename=str(temp_file), actual_filename=temp_file_enc, owner=current_user)
        db.session.add(new_file)
        db.session.commit()
        return redirect(url_for('files.home'))
    return render_template('upload.html', title='Upload', form=form, password_request="True")

@files.route("/shares", methods=['GET', 'POST'])
@login_required
def shares():
    if str(request.args.get("message")) == 'filedel':
        flash('Your file has been deleted', 'file-deleted')
    elif str(request.args.get("message")) == 'fileshare':
        flash('Your file has been shared', 'file-share')
    form = FileOptionsForm()
    if form.validate_on_submit():
        if request.form.get('submit_download') == 'Enter':
            # Pass the users' entered password and the sharer that is
            # passed using an additional field. [[ form.helper_field.data is the username that shareed ]]

            decrypted_file = app_utils.file_decryption(current_user.username, form.helper_field.data, form.input_field.data)

            return send_from_directory(directory="../" + current_current_app.config['UPLOAD_FOLDER'], filename=form.helper_field.data, as_attachment=True)
    files = User.query.filter_by(id=current_user.id).first()
    files_shared = files.files_shared

    # Extracting the usernames from the shared files
    usernames = []
    for file in files_shared:
        user = User.query.filter_by(id=file.owner_id).first().username
        usernames.append(user)
    return render_template('shares.html', files=files_shared, form=form, usernames=usernames)
