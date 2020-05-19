import os
import base64
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, flash, session, \
    abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
import onetimepass
import pyqrcode

# create application and get settings
app = Flask(__name__)
app.config.from_object('config')

# initialize boostrapp, db, loginmanager apps
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)


class User(UserMixin, db.Model):
    # Definition User model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))
    #  Created Secret Key
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # Generated secret key randomly
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    # Functions for creating user and initilaize it
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        # vierfy userinput and secret TOTP 
        return onetimepass.valid_totp(token, self.otp_secret)


@lm.user_loader
def load_user(user_id):
    # User loader callback for Flask-Login
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    # Registration form
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    # Login form
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    token = StringField('Token', validators=[Required(), Length(6, 6)])
    submit = SubmitField('Login')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # User registiration route
    if current_user.is_authenticated:
        # Loginned check
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists. Choice different username')
            return redirect(url_for('register'))
        # Add new user
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()

        # Redirect to t2a page with passing username in session
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)


@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
    # This page contains sensitive qr code and cache is disabled
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # expire sesion using key username
    del session['username']

    # Render QR code
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/login', methods=['GET', 'POST'])
def login():
    # User login route
    if current_user.is_authenticated:
        # Loginned check
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('Wrong username, password or otp token.')
            return redirect(url_for('login'))

        # Succes Login
        login_user(user)
        flash('Succesful Login using 2fa')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    # Logout Route
    logout_user()
    return redirect(url_for('index'))


# Create DB if not exist
db.create_all()

# Keep debug true for development,run  rebuild and run server every changes code 
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
