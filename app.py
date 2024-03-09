from flask import Flask, render_template, request, redirect, url_for, session
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from pymongo.server_api import ServerApi
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Set Flask secret key
app.secret_key = os.environ.get('FLASK_SECRET_KEY', '4d9a83f7a6d82e2b78a2f7e20bc13eb1')

# MongoDB connection details
uri = "mongodb+srv://pavan:54321@cluster0.0y4gult.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri, server_api=ServerApi('1'))
db = client.get_database("data")
users_collection = db.get_collection("users")

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users_collection.find_one({'email': email})

        if user and bcrypt.check_password_hash(user['password'], password):
            session['user'] = user['email']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid email or password. Please try again.')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('signup.html', error='Passwords do not match. Please try again.')

        existing_user = users_collection.find_one({'email': email})

        if existing_user:
            return render_template('signup.html', error='User with this email already exists. Please login.')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users_collection.insert_one({'email': email, 'password': hashed_password})
            session['user'] = email
            return redirect(url_for('dashboard'))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return 'Welcome to the Dashboard'
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
