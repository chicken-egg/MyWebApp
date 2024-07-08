from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
import cryptography
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import re
app = Flask(__name__)
# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'
# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
# Password below must be changed to match root password specified at server installation
# Lab computers use the root password `mysql`
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'pythonlogin'
#DO NOTE THAT THE MYSQL SERVER INSTANCE IN THE LAB IS RUNNING ON PORT 3360.
#Please make necessary change to the above MYSQL_PORT config
app.config['MYSQL_PORT'] = 3306
# Intialize MySQL
mysql = MySQL(app)
bcrypt = Bcrypt()
# http://localhost:5000/MyWebApp/ - this will be the login page, we need to use both GET and POST
#requests


#HOHO your mom

@app.route('/login/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            # Check if account is locked
            if account['failed_attempts'] >= 5:
                last_failed_attempt_time = account['last_failed_attempt']
                lock_period = timedelta(minutes=1)
                unlock_time = last_failed_attempt_time + lock_period

                if datetime.now() < unlock_time:
                    msg = 'Account is locked. Please try again later.'
                    return render_template('index.html', msg=msg)

            # Check password
            user_hashpwd = account['password']
            if bcrypt.check_password_hash(user_hashpwd, password):
                # Reset failed attempts after successful login
                cursor.execute('UPDATE accounts SET failed_attempts = 0, last_failed_attempt = NULL WHERE id = %s', (account['id'],))
                mysql.connection.commit()

                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']

                # Data decryption (should do in database)
                encrypted_email = account['email'].encode()

                # file = open('symmetric.key', 'rb')
                # key = file.read()
                # file.close()

                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM accounts WHERE encryption_key = %s', (key,))
                account = cursor.fetchone()

                f = Fernet(key)
                decrypted_email = f.decrypt(encrypted_email)

                return redirect(url_for('home'))
            else:
                # Increment failed attempts
                new_failed_attempts = account['failed_attempts'] + 1
                cursor.execute('UPDATE accounts SET failed_attempts = %s, last_failed_attempt = %s WHERE id = %s',
                               (new_failed_attempts, datetime.now(), account['id']))
                mysql.connection.commit()

                if new_failed_attempts >= 5:
                    msg = 'Account is locked. Please try again later.'
                else:
                    msg = 'Incorrect username/password!'
        else:
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)




# http://localhost:5000/MyWebApp/logout - this will be the logout page
@app.route('/MyWebApp/logout')
def logout():
   # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))


# http://localhost:5000/MyWebApp/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/MyWebApp/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # key is generate
        key = Fernet.generate_key()
        # write bytes (wb) to file (problem - send one key for different people)
        with open("symmetric.key", "wb") as fo:
            fo.write(key)
        # Initialize Fernet Classkey
        f = Fernet(key)
    
        # convert text to bytes
        email = email.encode()
        # plaintext converted to ciphertext
        encrypted_email = f.encrypt(email)

        hashpwd = bcrypt.generate_password_hash(password)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO accounts (username, password, email, failed_attempts, last_failed_attempt, encryption_key) VALUES (%s, %s, %s, %s, %s, %s)',
            (username, hashpwd, encrypted_email, 0, None, key)
        )
        mysql.connection.commit()
        msg = 'You have successfully registered!'
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
        # Show registration form with message (if any)
    return render_template('register.html', msg=msg)

# http://localhost:5000/MyWebApp/home - this will be the home page, only accessible for loggedin users
@app.route('/MyWebApp/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'])
        # User is not loggedin redirect to login page
    return redirect(url_for('login'))


# http://localhost:5000/MyWebApp/profile - this will be the profile page, only accessible for loggedin users
@app.route('/MyWebApp/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


if __name__== '__main__':
   app.run()
