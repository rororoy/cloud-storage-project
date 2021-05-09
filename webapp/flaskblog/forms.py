from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
import re
from flaskblog.models import User

class PasswordStrength(object):
    def __init__(self, message=None):
        if not message:
            message = 'Your password should contain at least one upper case character, one number and one symbol.'
        self.message = message

    def __call__(self, form, field):
        password = field.data
        regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]') 
        if regex.search(password) != None and any(chr.isdigit() for chr in password) and any(x.isupper() for x in password):
        	pass
        else:
            raise ValidationError(self.message)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=16), Regexp('^\w+$', message="Username must contain only letters numbers or underscore")])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=32, message='Password length should be between 8 characters and 32.'), PasswordStrength()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    

	# Costum validators to check if fields are free to use
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        
        # If user isnt None
        if user:
            raise ValidationError('This username is already taken')

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('This email is already registered')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateAccountCredsForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=16), Regexp('^\w+$', message="Username must contain only letters numbers or underscore")])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')
    

	# Costum validators to check if fields are free to use
    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            # If user isnt None
            if user:
                raise ValidationError('This username is already taken')

    def validate_email(self, email):
        if email.data != current_user.email:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError('This email is already registered')

