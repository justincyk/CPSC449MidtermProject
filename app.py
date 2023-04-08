from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, make_response
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
import pymysql
from datetime import timedelta
from flask_cors import CORS
import re
from functools import wraps
import jwt


app = Flask(__name__, template_folder='templates')

cors = CORS(app, resources={r"/*": {"origins": "*"}})

SECRET = "sufferin' succotash!"

app.secret_key = 'happykey'
app.permanent_session_lifetime = timedelta(minutes=10)

# To connect MySQL database
conn = pymysql.connect(
        host='localhost',
        user='s1akr', # set user to the username of your account - prob "root"
        password = "hellomahbebe", # Change password to password you set for your database
        db='449_midterm',
		cursorclass=pymysql.cursors.DictCursor
        )
cur = conn.cursor()

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
@app.route('/login', methods = ['POST'])
def login():
	data = request.form
	username = data.get('username')
	password = data.get('password')

	# if required information is not present
	if not data or not username or not password:
		abort(401, description="username and password is required to login")

	# use information to retreive account
	cur.execute('select * from Accounts where username = % s and password = % s', (username, password))
	conn.commit()
	account = cur.fetchone()

	# if one exists and password matches
	if account and account['Password'] == password:
		# encode jwt
		user = {
			'username': account['Username'],
	  	'first name': account['FirstName'],
			'last name': account['LastName']
		}
		encoded_jwt = jwt.encode(user, SECRET, algorithm='HS256')
		# set as cookie
		resp = make_response({'message': 'login successful!!'}, 200)
		resp.set_cookie('token', encoded_jwt)
		return resp
	else:
		# abort(401, description="incorrect username and/or password")
		# swap commenting with above code to get postman to work properly after a successful login:
		resp = make_response({'message': 'incorrect username and/or password'}, 401)
		resp.set_cookie('token', '', expires=0)
		return resp


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
   return redirect(url_for('login'))

@app.route('/uploader', methods = ['GET', 'POST'])
def upload():
   if request.method == 'POST':
      f = request.files['file']
      f.save(secure_filename(f.filename))
      return 'file uploaded successfully'

if __name__ == '__main__':
   app.run(host='localhost', port = int('8000'), debug = False)
