from functools import wraps
from flask import Flask, request, redirect, url_for, render_template, session
from flask_pymongo import PyMongo, ObjectId
from datetime import datetime
import hashlib


app = Flask(__name__)
app.secret_key = 'citybois'

app.config["MONGO_URI"] = "mongodb://localhost:27017/cityboys"

mongo = PyMongo(app)

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            message = 'Please authenticate first!'
            alert_type = 'danger'
            return redirect(url_for('login', next=request.url, message=message, alert_type=alert_type))
        else:
            return f(*args, **kwargs)
    return decorated_function


def create_demoadmin():
    role = 'staff'
    fullname = 'Super Admin'
    username = 'superadmin'
    password = '1234'
    created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

    password = hashlib.md5(password.encode('utf-8')).hexdigest()
    user = {
        "role": role,
        "fullname": fullname,
        "username": username,
        "password": password,
        "created_by": "system",
        "created_datetime": created_datetime,
        "modified_datetime": created_datetime
    }
    results = mongo.db.users.insert_one(user)
    print ('Created User superadmin (id: %s)' % results.inserted_id)


def create_demostudent():
    role = 'student'
    fullname = 'Demo Student'
    username = 'demostudent'
    password = '1234'

    now = datetime.now()
    created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

    password = hashlib.md5(password.encode('utf-8')).hexdigest()
    user = {
        "role": role,
        "fullname": fullname,
        "username": username,
        "password": password,
        "created_by": "system",
        "created_datetime": created_datetime,
        "modified_datetime": created_datetime
    }
    results = mongo.db.users.insert_one(user)
    print ('Created User demostudent (id: %s)' % results.inserted_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    '''
    For Demo sake
    '''
    superadmin = mongo.db.users.find_one({"username": "superadmin"})
    demostudent = mongo.db.users.find_one({"username": "demostudent"})
    if superadmin is None:
        create_demoadmin()
    if demostudent is None:
        create_demostudent()

    message = ''
    alert_type = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username and password:
            user_details = mongo.db.users.find_one({"username": username})

            if user_details:
                password = hashlib.md5(password.encode('utf-8')).hexdigest()
                if user_details['password'] == password:
                    session['id'] = str(user_details['_id'])
                    session['role'] = user_details['role']
                    session['fullname'] = user_details['fullname']
                    session['username'] = username
                    return redirect(url_for('dashboard'))
            else:
                message = 'Incorrect username or password!'
                alert_type = 'danger'
                return render_template('login.html', message=message, alert_type=alert_type)
        else:
            message = 'Please enter your username and password!'
            alert_type = 'danger'
            return render_template('login.html', message=message, alert_type=alert_type)
    return render_template('login.html')


@app.route('/logout')
def logout():
    '''
    Unset Sessions
    '''
    session.pop('role')
    session.pop('fullname')
    session.pop('username')

    return redirect(url_for('login'))

@app.route('/')
@auth_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/users/list')
@auth_required
def list_users(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        users_list = mongo.db.users.find()
        return render_template('list_users.html', message=message, alert_type=alert_type, users_list=users_list)

@app.route('/users/create', methods=['GET', 'POST'])
@auth_required
def create_user():
        message = ''
        alert_type = ''
        if request.method == 'POST':
            role = request.form.get('role')
            fullname = request.form.get('fullname')
            username = request.form.get('username')
            password = request.form.get('password')

            if role and fullname and username and password:
                now = datetime.now()
                created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
                created_by = session['username']

                password = hashlib.md5(password.encode('utf-8')).hexdigest()
                user = {
                    "role": role,
                    "fullname": fullname,
                    "username": username,
                    "password": password,
                    "created_by": created_by,
                    "created_datetime": created_datetime,
                    "modified_datetime": created_datetime
                }
                results = mongo.db.users.insert_one(user)
                message = 'Successfully created user (id: %s)' % results.inserted_id
                alert_type = 'success'
                return redirect(url_for('list_users', message=message, alert_type=alert_type))
            else:
                message = "Please fill in all the fields!"
                alert_type = 'danger'
        return render_template('create_user.html', message=message, alert_type=alert_type)

@app.route('/users/edit/<userid>', methods=['GET', 'POST'])
@auth_required
def edit_user(userid):
        message = ''
        alert_type = ''
        user_details = mongo.db.users.find_one({"_id": ObjectId(userid)})

        if request.method == 'POST':
            role = request.form.get('role')
            fullname = request.form.get('fullname')
            username = request.form.get('username')
            password = request.form.get('password')

            if role and fullname and username:
                if password:
                    password = hashlib.md5(password.encode('utf-8')).hexdigest()
                else:
                    password = user_details['password']

                now = datetime.now()
                modified_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
                modified_by = session['username']

                user_id = {
                    "_id": ObjectId(userid)
                }
                user = {
                    "$set": {
                        "role": role,
                        "fullname": fullname,
                        "username": username,
                        "password": password,
                        "modified_by": modified_by,
                        "modified_datetime": modified_datetime
                    }
                }
                results = mongo.db.users.find_one_and_update(user_id, user)
                message = 'Successfully edited user (id: %s)' % results['_id']
                alert_type = 'success'
                return redirect(url_for('list_users', message=message, alert_type=alert_type))
            else:
                message = "Please fill in all the fields!"
                alert_type = 'danger'
        return render_template('edit_user.html', message=message, alert_type=alert_type, user=user_details)

@app.route('/users/delete/<userid>', methods=['GET', 'POST'])
@auth_required
def delete_user(userid):
        message = ''
        alert_type = ''
        user_details = mongo.db.users.find_one({"_id": ObjectId(userid)})

        if request.method == 'POST':
            user_id = {
                "_id": ObjectId(userid)
            }

            results = mongo.db.users.find_one_and_delete(user_id)
            message = 'Successfully deleted user (id: %s)' % results['_id']
            alert_type = 'success'
            return redirect(url_for('list_users', message=message, alert_type=alert_type))

        return render_template('delete_user.html', message=message, alert_type=alert_type, user=user_details)

if __name__ == '__main__':
    app.run(debug=True)