from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp

class UploadForm(FlaskForm):
    password = PasswordField('',  validators=[DataRequired(), Length(min=1, max=32, message='Enter a password')])
    submit = SubmitField('Submit')

class FileOptionsForm(FlaskForm):
    helper_field = StringField('Helper')
    input_field = StringField('Field', validators=[DataRequired()])
    submit_download = SubmitField('Download')
    submit_share = SubmitField('Share')
    submit_delete = SubmitField('Delete')

class RegistrationForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=1, max=32, message='Enter a password')])
    submit = SubmitField('Sign Up')
