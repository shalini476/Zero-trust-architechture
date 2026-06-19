from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, ValidationError
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
from app.models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    captcha = StringField('CAPTCHA Code', validators=[DataRequired(), Length(min=5, max=5, message="CAPTCHA must be exactly 5 characters.")])
    submit = SubmitField('Log In')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80),
        Regexp('^[A-Za-z0-9_.]+$', message="Username must contain only letters, numbers, dots or underscores.")
    ])
    email = StringField('Email Address', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    role = SelectField('Role', choices=[
        ('employee', 'Employee'),
        ('admin', 'Administrator'),
        ('hr', 'Human Resources'),
        ('finance', 'Finance')
    ], validators=[DataRequired()])
    
    security_question = SelectField('Security Question', choices=[
        ('What was the name of your first school?', 'What was the name of your first school?'),
        ('What is your mother\'s maiden name?', 'What is your mother\'s maiden name?'),
        ('What was your first pet\'s name?', 'What was your first pet\'s name?'),
        ('In what city were you born?', 'In what city were you born?')
    ], validators=[DataRequired()])
    security_answer = StringField('Security Answer', validators=[DataRequired(), Length(min=2)])
    backup_email = StringField('Backup Email Address (Optional)', validators=[Length(max=120)])

    submit = SubmitField('Register Account')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose another.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email address already registered.')

    def validate_backup_email(self, backup_email):
        if backup_email.data:
            # Simple check to make sure it doesn't match primary email
            if backup_email.data == self.email.data:
                raise ValidationError('Backup email cannot be the same as your primary email.')


class OTPForm(FlaskForm):
    otp_code = StringField('OTP Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message="OTP must be exactly 6 digits."),
        Regexp('^[0-9]+$', message="OTP must contain only numbers.")
    ])
    submit = SubmitField('Verify OTP')


class SecurityQuestionForm(FlaskForm):
    security_answer = StringField('Answer', validators=[DataRequired()])
    submit = SubmitField('Verify Identity')
