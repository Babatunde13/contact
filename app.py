from flask import Flask, request, url_for, render_template, redirect, flash, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Thisisasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/DELL INSPIRON 14/Downloads/Compressed/Flask/Python Code/Test/database.db'

Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#creating model table for the login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(60))
    #children = relationship("Contact")

#creating model table for the contact
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(50))
    location = db.Column(db.String(100))
    owner = db.relationship('User', backref='contact')

    def __init__(self, name, email, phone, location, owner):
        self.name = name
        self.email = email
        self.phone = phone
        self.location = location
        self.owner = owner

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(),
                            Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(),
                                Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(),
                            Length(min=4, max=15)])
    email = StringField('email', validators=[InputRequired(),
                            Email(message='Invalid email'),Length(max=50)])
    password = PasswordField('password', validators=[InputRequired(),
                                Length(min=8, max=50)])



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect Password')
        else:
            flash('Incorrect Username')
    return render_template('login.html', form = form)

@app.route('/signup', methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username = form.username.data,
                        email = form.email.data,
                        password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('You were Successfully registered')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

#This is the dashboard route where we are going to query on all our Contact data
@app.route('/dashboard')
@login_required
def dashboard():
    all_data = Contact.query.all()
    return render_template('dashboard.html')

#this route is for inserting data to mysql database via html forms
@app.route('/insert', methods = ['POST'])
def insert():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        location = request.form['location']

        my_data = Contact(name, email, phone, location, (owner=request.user))
        db.session.add(my_data)
        db.session.commit()

        flash("Contact added successfully")

        return redirect(url_for('dashboard'))

#this is our update route where we are going to update our contact
@app.route('/update', methods = ['GET', 'POST'])
def update():

    if request.method == 'POST':
        my_data = Contact.query.get(request.form.get('id'))

        my_data.name = request.form['name']
        my_data.email = request.form['email']
        my_data.phone = request.form['phone']
        my_data.location = request.form['location']

        db.session.commit()
        flash("Contact Updated Successfully")

        return redirect(url_for('dashboard'))

#This route is for deleting our contact
@app.route('/delete/<id>/', methods = ['GET', 'POST'])
def delete(id):
    my_data = Contact.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("Contact Deleted Successfully")

    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
