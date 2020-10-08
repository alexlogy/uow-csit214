from functools import wraps
from flask import Flask, request, redirect, url_for, render_template, session
from flask_pymongo import PyMongo, ObjectId
import datetime
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

def role_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session['role'] == 'Student':
            message = "You're not authorized to perform this function!"
            alert_type = 'danger'
            return redirect(url_for('dashboard', next=request.url, message=message, alert_type=alert_type))
        else:
            return f(*args, **kwargs)
    return decorated_function

def create_demoadmin():
    role = 'Staff'
    fullname = 'Super Admin'
    username = 'superadmin'
    password = '1234'

    now = datetime.datetime.now()
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
    role = 'Student'
    fullname = 'Demo Student'
    username = 'demostudent'
    password = '1234'

    now = datetime.datetime.now()
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
    session.pop('id')
    session.pop('role')
    session.pop('fullname')
    session.pop('username')

    return redirect(url_for('login'))

@app.route('/changepassword', methods=['GET', 'POST'])
@auth_required
def change_password():
        message = ''
        alert_type = ''
        user_details = mongo.db.users.find_one({"_id": ObjectId(session['id'])})

        if request.method == 'POST':
            password = request.form.get('password')

            if password:
                password = hashlib.md5(password.encode('utf-8')).hexdigest()
            else:
                message = 'Nothing was changed!'
                alert_type = 'info'
                return redirect(url_for('dashboard', message=message, alert_type=alert_type))

            now = datetime.datetime.now()
            modified_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
            modified_by = session['username']

            user_id = {
                "_id": ObjectId(session['id'])
            }
            user = {
                "$set": {
                    "password": password,
                    "modified_by": modified_by,
                    "modified_datetime": modified_datetime
                }
            }
            results = mongo.db.users.find_one_and_update(user_id, user)
            message = 'Successfully change password for user (id: %s)' % results['_id']
            alert_type = 'success'
            return redirect(url_for('dashboard', message=message, alert_type=alert_type))
        return render_template('change_password.html', message=message, alert_type=alert_type, user=user_details)


@app.route('/')
@auth_required
def dashboard(message='', alert_type=''):
    if request.args.get('message') and request.args.get('alert_type'):
        message = request.args.get('message')
        alert_type = request.args.get('alert_type')

    return render_template('dashboard.html', message=message, alert_type=alert_type)


'''
Sessions
'''
@app.route('/sessions/list-bookings')
@auth_required
def list_bookings(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        if session['role'] == 'Student':
            sessions_list = mongo.db.sessions.aggregate([
                {
                  "$match": {
                      "booked_by": session['username']
                  }
                },
                {
                    "$lookup": {
                        "from": "channels",
                        "localField": "channelid",
                        "foreignField": "_id",
                        "as": "channel_info"
                    }
                }
            ])
        else:
            sessions_list = mongo.db.sessions.aggregate([
                {
                    "$lookup": {
                        "from": "channels",
                        "localField": "channelid",
                        "foreignField": "_id",
                        "as": "channel_info"
                    }
                }
            ])

        return render_template('list_bookings.html', message=message, alert_type=alert_type, sessions_list=sessions_list)

@app.route('/sessions/book/<channelid>')
@auth_required
def book_session(channelid, message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        channel_details = mongo.db.channels.find_one({"_id": ObjectId(channelid)})
        booking_count = mongo.db.sessions.find(
            {
                "channelid": ObjectId(channelid),
                "status": "Booked"
            }
        ).count()

        if (booking_count < channel_details['capacity']):
            now = datetime.datetime.now()
            created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
            booked_by = session['username']

            session_details = {
                "channelid": ObjectId(channelid),
                "status": "Booked",
                "booked_by": booked_by,
                "created_datetime": created_datetime,
                "modified_datetime": created_datetime
            }
            results = mongo.db.sessions.insert_one(session_details)
            message = 'Successfully created session (session id: %s)' % results.inserted_id
            alert_type = 'success'
            return redirect(url_for('list_bookings', message=message, alert_type=alert_type))
        else:
            message = 'Session is fully booked! Please choose another channel! (channel id: %s)' % channelid
            alert_type = 'danger'
            return redirect(url_for('list_channels', message=message, alert_type=alert_type))

@app.route('/sessions/cancel/<sessionid>')
@auth_required
def cancel_session(sessionid):
    session_detail = mongo.db.sessions.find_one({"_id": ObjectId(sessionid)})
    now = datetime.datetime.now()
    modified_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

    session_id = {
        "_id": ObjectId(sessionid)
    }
    session_params = {
        "$set": {
            "status": 'Canceled',
            "canceled_by": session['username'],
            "modified_datetime": modified_datetime
        }
    }
    results = mongo.db.sessions.find_one_and_update(session_id, session_params)
    message = 'Successfully canceled booking (id: %s)' % results['_id']
    alert_type = 'success'
    return redirect(url_for('list_bookings', message=message, alert_type=alert_type))


'''
Channels
'''
@app.route('/channels/list')
@auth_required
def list_channels(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        if session['role'] == 'Student':
            today_date = datetime.date.today().strftime("%d/%m/%Y")
            search_range = {
                "channeldate": {
                "$gte": today_date
                }
            }
            channel_list = mongo.db.channels.find(search_range)
        else:
            channel_list = mongo.db.channels.find()

        sessions_list = mongo.db.sessions.find()

        booking_dict = {}
        for session_detail in sessions_list:
            booking_count = mongo.db.sessions.find(
                {
                    "channelid": session_detail['channelid'],
                    "status": "Booked"
                }
            ).count()
            booking_dict[session_detail['channelid']] = booking_count
        return render_template('list_channels.html', message=message, alert_type=alert_type, channels_list=channel_list, booking_dict=booking_dict)


@app.route('/channels/create', methods=['GET', 'POST'])
@auth_required
@role_check
def create_channel(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        if request.method == 'POST':
            channelname = request.form.get('channelname')
            channeldate = request.form.get('channeldate')
            starttime = request.form.get('starttime')
            endtime = request.form.get('endtime')
            capacity = int(request.form.get('capacity'))

            if channelname and channeldate and starttime and endtime and capacity:
                try:
                    date_validation = datetime.datetime.strptime(channeldate, "%d/%m/%Y")
                    starttime_validation = datetime.datetime.strptime(starttime, "%H%M")
                    endtime_validation = datetime.datetime.strptime(endtime, "%H%M")
                except ValueError:
                    message = 'Invalid Date/Time Format! (dd/mm/yy, HHHH)'
                    alert_type = 'danger'
                    return redirect(url_for('create_channel', message=message, alert_type=alert_type))

                if (endtime > starttime):
                    if (isinstance(capacity, int) and (capacity > 0)):
                        now = datetime.datetime.now()
                        created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
                        created_by = session['username']

                        channel = {
                            "channelname": channelname,
                            "channeldate": channeldate,
                            "starttime": starttime,
                            "endtime": endtime,
                            "capacity": capacity,
                            "created_by": created_by,
                            "created_datetime": created_datetime,
                            "modified_datetime": created_datetime
                        }
                        results = mongo.db.channels.insert_one(channel)
                        message = 'Successfully created channel (id: %s)' % results.inserted_id
                        alert_type = 'success'
                        return redirect(url_for('list_channels', message=message, alert_type=alert_type))
                    else:
                        message = 'Invalid Channel Capacity!'
                        alert_type = 'danger'
                        return redirect(url_for('create_channel', message=message, alert_type=alert_type))
                else:
                    message = 'Invalid Start and End Time'
                    alert_type = 'danger'
                    return redirect(url_for('create_channel', message=message, alert_type=alert_type))
            else:
                message = "Please fill in all the fields!"
                alert_type = 'danger'
        return render_template('create_channel.html', message=message, alert_type=alert_type)

@app.route('/channels/edit/<channelid>', methods=['GET', 'POST'])
@auth_required
@role_check
def edit_channel(channelid, message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        channel_details = mongo.db.channels.find_one({"_id": ObjectId(channelid)})

        if request.method == 'POST':
            channelname = request.form.get('channelname')
            channeldate = request.form.get('channeldate')
            starttime = request.form.get('starttime')
            endtime = request.form.get('endtime')
            capacity = int(request.form.get('capacity'))

            if channelname and channeldate and starttime and endtime and capacity:
                try:
                    date_validation = datetime.datetime.strptime(channeldate, "%d/%m/%Y")
                    starttime_validation = datetime.datetime.strptime(starttime, "%H%M")
                    endtime_validation = datetime.datetime.strptime(endtime, "%H%M")
                except ValueError:
                    message = 'Invalid Date/Time Format! (dd/mm/yy, HHHH)'
                    alert_type = 'danger'
                    return redirect(url_for('create_channel', message=message, alert_type=alert_type))

                if (endtime > starttime):
                    if (isinstance(capacity, int) and (capacity > 0)):
                        now = datetime.datetime.now()
                        modified_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
                        modified_by = session['username']

                        channel_id = {
                            "_id": ObjectId(channelid)
                        }

                        channel = {
                            "$set": {
                                "channelname": channelname,
                                "channeldate": channeldate,
                                "starttime": starttime,
                                "endtime": endtime,
                                "capacity": capacity,
                                "modified_by": modified_by,
                                "modified_datetime": modified_datetime
                            }
                        }
                        results = mongo.db.channels.find_one_and_update(channel_id, channel)
                        message = 'Successfully edited channel (id: %s)' % results['_id']
                        alert_type = 'success'
                        return redirect(url_for('list_channels', message=message, alert_type=alert_type))
                    else:
                        message = 'Invalid Channel Capacity!'
                        alert_type = 'danger'
                        return redirect(url_for('edit_channel', message=message, alert_type=alert_type))
                else:
                    message = 'Invalid Start and End Time'
                    alert_type = 'danger'
                    return redirect(url_for('edit_channel', message=message, alert_type=alert_type))
            else:
                message = "Please fill in all the fields!"
                alert_type = 'danger'
        return render_template('edit_channel.html', message=message, alert_type=alert_type, channel=channel_details)


@app.route('/channels/delete/<channelid>', methods=['GET', 'POST'])
@auth_required
@role_check
def delete_channel(channelid):
        message = ''
        alert_type = ''
        channel_details = mongo.db.channels.find_one({"_id": ObjectId(channelid)})

        if request.method == 'POST':
            channel_id = {
                "_id": ObjectId(channelid)
            }

            results = mongo.db.channels.find_one_and_delete(channel_id)
            message = 'Successfully deleted channel (id: %s)' % results['_id']
            alert_type = 'success'
            return redirect(url_for('list_channels', message=message, alert_type=alert_type))

        return render_template('delete_channel.html', message=message, alert_type=alert_type, channel=channel_details)


'''
Users
'''

@app.route('/users/list')
@auth_required
@role_check
def list_users(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        users_list = mongo.db.users.find()
        return render_template('list_users.html', message=message, alert_type=alert_type, users_list=users_list)

@app.route('/users/create', methods=['GET', 'POST'])
@auth_required
@role_check
def create_user():
        message = ''
        alert_type = ''
        if request.method == 'POST':
            role = request.form.get('role')
            fullname = request.form.get('fullname')
            username = request.form.get('username')
            password = request.form.get('password')

            if role and fullname and username and password:
                now = datetime.datetime.now()
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
@role_check
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

                now = datetime.datetime.now()
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
@role_check
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