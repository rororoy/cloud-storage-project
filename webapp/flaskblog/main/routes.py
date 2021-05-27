from flask import render_template, request, Blueprint
from flaskblog.models import Files, User
from flask_login import login_required

main = Blueprint('main', __name__)

@main.route('/admin')
@login_required
def admin():
    # Will pass: number of files saved,
    # a dictionary with a name of a user and the number of files he has uploade.
    number_of_files = db.session.query(Files).count()
    users_and_files = db.session.query(User)

    users = {"User": "Files"}
    for row in users_and_files:
        users[row.username] = len(row.files)

    return render_template('admin.html', title='Manage Site', number_of_files=number_of_files, users=users)

@main.route("/about")
def about():
    return render_template('about.html', title='About')
