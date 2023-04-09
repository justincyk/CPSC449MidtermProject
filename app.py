from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
from dotenv import load_dotenv
import os
import pymysql
from datetime import timedelta
from flask_cors import CORS
import re

load_dotenv()

app = Flask(__name__, template_folder='templates')

cors = CORS(app, resources={r"/*": {"origins": "*"}})


app.secret_key = 'happykey'
app.permanent_session_lifetime = timedelta(minutes=10)

# To connect MySQL database
conn = pymysql.connect(
        host='localhost',
        user= os.getenv("USER"), # set user to the username of your account - prob "root"
        password = os.getenv("PASSWORD"), # Change password to password you set for your database
        db='449_midterm',
		cursorclass=pymysql.cursors.DictCursor
        )
cur = conn.cursor()

# Login page
@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
	msg = ''
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form:

		session.permanent = True
		username = request.form['username']
		password = request.form['password']
		cur.execute('SELECT * FROM Accounts WHERE Username = % s AND Password = % s', (username, password, ))
		conn.commit()
		account = cur.fetchone()
		if account:

			session['loggedin'] = True
			session['id'] = account['id']
			session['Username'] = account['Username']
			msg = 'Logged in successfully !'
			# direct them to the upload a file page if they successfully log in
			return render_template('upload.html', msg = msg)
		else:
			msg = 'Incorrect username / password !'
	else:
		# if "loggedin" in session:
		# 	# redirect them to the upload a file page if they are already logged in
		# 	return redirect(url_for("upload_file"))
		return render_template('login.html', msg = msg)
	

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/register', methods =['GET', 'POST'])
def register():
	msg = ''
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'firstName' in request.form and 'lastName' in request.form:
		print('reached')
		username = request.form['username']
		password = request.form['password']
		retypePassword = request.form['retypePassword']
		email = request.form['email']
		firstName = request.form['firstName']
		lastName = request.form['lastName']
		cur.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
		account = cur.fetchone()
		print(account)
		conn.commit()
		if account:
			msg = 'Account already exists!'
		elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
			msg = 'Invalid email address!'
		elif not re.match(r'[A-Za-z0-9]+', username):
			msg = 'name must contain only characters and numbers!'
		elif not re.match(retypePassword, password):
			msg = 'passwords do not match!'
		else:
			cur.execute('INSERT INTO accounts VALUES (NULL, % s, % s, % s, % s, % s)', (username, password, email, firstName, lastName))
			conn.commit()

			msg = 'You have successfully registered!'
	elif request.method == 'POST':
		msg = 'Please fill out the form!'
	return render_template('register.html', msg = msg)


@app.route('/upload')
def upload_file():
   # Make sure they are logged in before accessing the upload page
   if 'loggedin' in session:
      return render_template("upload.html")
   # If not logged in, direct them to the login page
   return redirect(url_for('login'))
	
@app.route('/uploader', methods = ['GET', 'POST'])
def upload():
   if request.method == 'POST':
      f = request.files['file']
      f.save(secure_filename(f.filename)) 
      return 'file uploaded successfully'
		
if __name__ == '__main__':
   app.run(debug = False)