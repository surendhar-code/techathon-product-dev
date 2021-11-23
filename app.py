# importing all the necessary python libraries for the application

from flask import Flask, render_template,request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import config
from flask_mail import Mail, Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

# WSGI application
app=Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = config.email
app.config['MAIL_PASSWORD'] = config.password
mail = Mail(app)

# configuring sqlite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# instance of sqlalchemy class
db = SQLAlchemy(app)

# instance of bcrypt for hashing the password
bcrypt = Bcrypt(app)

app.secret_key = 'yudohfkgbnxvsfagbfm@#%&(^(__&3587269621%$()$^%^'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100),unique=True, nullable = False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(120),nullable=False)
    password = db.Column(db.String(60), nullable=False)
    confirm_password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False,nullable=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}')"

@app.route('/student')
def student_page():
    username = session['username']
    return render_template('student.html',username=username)

@app.route('/teacher')
def teacher_page():
    username = session['username']
    return render_template('teacher.html',username=username)

@app.route('/admin')
def admin():
    username = session['username']
    return render_template('admin.html',username=username)

@app.route('/', methods=['GET','POST'])
def signup():
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        users = User.query.all()
        existing_accounts = []
        for user in users:
            account = user.email
            existing_accounts.append(account)
        if email in existing_accounts:
            message="Account already exists...Try with different email address"
        elif password!=confirm_password:
            message="Your Password and Confirm Password not matched. Please type correct password..."
        else:
            # hashing the password and confirm password before storing it into the database.
            hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
            hash_confirm_password = bcrypt.generate_password_hash(confirm_password).decode('utf-8')

            # add the values into the database
            user = User(username=username, email=email, role=role, password=hash_password, confirm_password = hash_confirm_password)

            db.session.add(user)
            db.session.commit()
            message = "Your account has been created! You are now able to log in', 'success'"
            return redirect(url_for('signin'))
    return render_template('signup.html', message=message)

@app.route('/signin',methods=['GET','POST'])
def signin():
    message=''
    if request.method =='POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        print(user)
        if user and bcrypt.check_password_hash(user.password,password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            session['role'] = user.role
            session['is_admin'] = user.is_admin
            session['loggedin'] = True
            if session['role'] == 'student':
                return redirect(url_for('student_page'))
            elif session['role'] == 'teacher':
                return redirect(url_for('teacher_page'))
            else:
                return redirect(url_for('admin'))

            
        else:
            message="Log in Unsuccessful. Please check username and password"
        
    
    return render_template("signin.html",message=message)

@app.route('/logout')
def logout():
    session.pop('loggedin', None) 
    session.pop('user_id',None)
    session.pop('is_admin',None)
    session.pop('email',None)
    session.pop('username',None)
    session.pop('role',None)
    return redirect(url_for('signin'))

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender=config.email,
                  recipients=user.email)
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    message = ''
    if request.method =='POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        send_reset_email(user)
        message = 'An email has been sent with instructions to reset your password.'
        return redirect(url_for('signin'))
    return render_template('reset_request.html',message=message)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    message = ''
    user = User.verify_reset_token(token)
    if user is None:
        message = 'That is an invalid or expired token'
        return redirect(url_for('reset_request'))
    if request.method == 'POST':
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        confirm_hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed_password
        user.confirm_password = confirm_hashed_password
        db.session.commit()
        
        return redirect(url_for('signin'))
    return render_template('reset_token.html',message=message)

            
            
            



















if __name__=='__main__':
    app.run(debug=True,use_reloader=False)