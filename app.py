from flask import Flask, request, redirect, url_for, render_template
from flask_pymongo import PyMongo, ObjectId
import hashlib

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/cityboys"

mongo = PyMongo(app)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
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

@app.route('/users/list')
def list_users(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        users_list = mongo.db.users.find()
        return render_template('list_users.html', message=message, alert_type=alert_type, users_list=users_list)

@app.route('/users/create', methods=['GET', 'POST'])
def create_user():
        message = ''
        alert_type = ''
        if request.method == 'POST':
            role = request.form.get('role')
            fullname = request.form.get('fullname')
            username = request.form.get('username')
            password = request.form.get('password')

            if role and fullname and username and password:
                password = hashlib.md5(password.encode('utf-8')).hexdigest()
                user = {
                    "role": role,
                    "fullname": fullname,
                    "username": username,
                    "password": password
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

                user_id = {
                    "_id": ObjectId(userid)
                }
                user = {
                    "$set": {
                        "role": role,
                        "fullname": fullname,
                        "username": username,
                        "password": password
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
