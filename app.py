from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, make_response
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
from dotenv import load_dotenv
import os
import pymysql
from datetime import timedelta
from flask_cors import CORS
import re
from functools import wraps
import jwt

load_dotenv()

app = Flask(__name__, template_folder='templates')

cors = CORS(app, resources={r"/*": {"origins": "*"}})

SECRET = "sufferin' succotash!"

app.secret_key = 'happykey'
app.permanent_session_lifetime = timedelta(minutes=10)

# file upload configs
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif']
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['UPLOAD_PATH'] = 'uploads'

# To connect MySQL database
conn = pymysql.connect(
        host='localhost',
        user= os.getenv("USERNAME"), # set user to the username of your account - prob "root"
        password = os.getenv("PASSWORD"), # Change password to password you set for your database
        db='449_midterm',
		cursorclass=pymysql.cursors.DictCursor
        )
cur = conn.cursor()

# Error handling

@app.errorhandler(400)
def bad_request(error):
    return jsonify(error=str(error)), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify(error=str(error)), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify(error=str(error)), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify(error=str(error)), 500

# login_required decorator definition
def login_required(func):
	@wraps(func)
	def decorated_func(*args, **kwargs):
		encoded_jwt = request.cookies.get('token')
		if encoded_jwt:
			user = jwt.decode(encoded_jwt, SECRET, algorithms=["HS256"])
			if user['username'] == 'admin': return func(*args, **kwargs)
		abort(401, description="Authorized access only! Please login.")
	return decorated_func

# login endpoint
@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
	msg = ''
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
		session.permanent = True
		data = request.form
		username = data.get('username')
		password = data.get('password')

	# if required information is not present
	# if not data or not username or not password:
	# 	abort(401, description="username and password is required to login")

	# use information to retreive account
		cur.execute('select * from Accounts where username = % s and password = % s', (username, password))
		conn.commit()
		account = cur.fetchone()

	# if one exists and password matches
		if account and account['Password'] == password:
			session['loggedin'] = True
			session['id'] = account['id']
			session['Username'] = account['Username']

			# encode jwt
			user = {
				'username': account['Username'],
			'first name': account['FirstName'],
				'last name': account['LastName']
			}
			encoded_jwt = jwt.encode(user, SECRET, algorithm='HS256')
			# set as cookie
			msg = 'Logged in successfully !'
			resp = make_response(render_template('upload.html', msg = msg), 200)
			resp.set_cookie('token', encoded_jwt)
			return resp
		else:
			# abort(401, description="incorrect username and/or password")
			# swap commenting with above code to get postman to work properly after a successful login:
			msg = 'Incorrect username / password !'
			resp = make_response(render_template('login.html', msg = msg), 401)
			resp.set_cookie('token', '', expires=0)
			return resp

	else:
		if "loggedin" in session:
			# redirect them to the upload a file page if they are already logged in
			return redirect(url_for("upload_file"))
		return render_template('login.html', msg = msg)


# protected endpoint
@app.route('/protected')
@login_required
def protected():
	# protected endpoint only authenticated users can access
	return {'message': 'You got in!  You must be special!! or just logged in...'}

# public enpoints
@app.route('/public')
def public():
	return {
		'message': 'You got in! Pfft...so what!! So did everyone else...',
		'view': 'public information'
	}

@app.route('/register', methods =['GET', 'POST'])
def register():
	msg = ''
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'firstName' in request.form and 'lastName' in request.form:
		print('reached')
		username = request.form['username']
		print(username)
		password = request.form['password']
		retypePassword = request.form['retypePassword']
		firstName = request.form['firstName']
		lastName = request.form['lastName']
		cur.execute('SELECT * FROM Accounts WHERE username = % s;', (username, ))
		account = cur.fetchone()
		print("accout: ", account)
		conn.commit()
		if account:
			msg = 'Account already exists!'
		elif not re.match(r'[A-Za-z0-9]+', username):
			msg = 'name must contain only characters and numbers!'
		elif not re.match(retypePassword, password):
			msg = 'passwords do not match!'
		else:
			cur.execute('INSERT INTO Accounts (FirstName, LastName, Username, Password) VALUES ( % s, % s, % s, % s);', (firstName, lastName, username, password))
			conn.commit()
@app.route('/unprotected')
def unprotected():
	return {
		'message': 'You got in! Pfft...so what!! So did everyone else...',
		'view': 'public information'
	}

@app.route('/freebies')
def freebies():
	return {
		'message': "You got in! Pfft...so what!! So did everyone else...",
		'view': 'public information'
	}

# endpoint to return a list of items that can be viewed publicly
@app.route('/sitemap')
def sitemap():
	return {
		'public endpoints': ['/public', '/unprotected', '/freebies'],
		'view': 'public information'
	}

@app.route('/upload')
def upload_file():
   # Make sure they are logged in before accessing the upload page
   if 'loggedin' in session:
      return render_template("upload.html")
   # If not logged in, direct them to the login page
   return redirect(url_for("login"))

@app.route('/uploader', methods = ['GET', 'POST'])
def upload():
	if request.method == 'POST':
		uploaded_file = request.files['file']
		filename = secure_filename(uploaded_file.filename)
		if filename != '':
			file_ext = os.path.splitext(filename)[1]
			if file_ext not in app.config['UPLOAD_EXTENSIONS']:
				abort(400)
			uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], filename))
			return redirect(url_for('upload_file'))
	else:
		return redirect(url_for('upload_file'))
if __name__ == '__main__':
   app.run(host='localhost', port = int('8000'), debug = False)
