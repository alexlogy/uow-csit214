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

def staff_role_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session['role'] == 'Staff':
            return f(*args, **kwargs)
        else:
            message = "You're not authorized to perform this function!"
            alert_type = 'danger'
            return redirect(url_for('dashboard', next=request.url, message=message, alert_type=alert_type))
    return decorated_function

def admin_role_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session['role'] == 'Admin':
            return f(*args, **kwargs)
        else:
            message = "You're not authorized to perform this function!"
            alert_type = 'danger'
            return redirect(url_for('dashboard', next=request.url, message=message, alert_type=alert_type))
    return decorated_function

def create_useradmin():
    role = 'Admin'
    fullname = 'Demo User Admin'
    username = 'useradmin'
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
    print ('Created User useradmin (id: %s)' % results.inserted_id)

def create_demostaff():
    role = 'Staff'
    fullname = 'Demo Staff'
    username = 'demostaff'
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
    print ('Created User demostaff (id: %s)' % results.inserted_id)

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

def create_demochannel():
    now = datetime.datetime.now()
    created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

    channel = {
        "channelname": "Demo Channel",
        "channeldate": "01/11/2020",
        "channelenddate": "30/11/2020",
        "capacity": 100,
        "created_by": "demostaff",
        "created_datetime": created_datetime,
        "modified_datetime": created_datetime
    }
    results = mongo.db.channels.insert_one(channel)
    print('Created Channel demochannel (id: %s)' % results.inserted_id)

def create_demosession():
    # Get Demo Channel ID
    demo_channel_result = mongo.db.channels.find_one({"channelname": "Demo Channel"})

    now = datetime.datetime.now()
    created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

    session_param = {
        "channelid": ObjectId(demo_channel_result['_id']),
        "sessiondate": "18/11/2020",
        "sessionstarttime": "08:00",
        "sessionendtime": "10:30",
        "created_by": "demostaff",
        "created_datetime": created_datetime,
        "modified_datetime": created_datetime
    }
    results = mongo.db.sessions.insert_one(session_param)
    print('Created Session demosession (id: %s)' % results.inserted_id)

def create_demobooking():
    # Get Demo Channel ID
    demo_channel_result = mongo.db.channels.find_one({"channelname": "Demo Channel"})
    demochannelid = demo_channel_result['_id']

    # Get Demo Session ID
    demo_session_result = mongo.db.sessions.find_one({'channelid': ObjectId(demochannelid) })
    demosessionid = demo_session_result['_id']

    now = datetime.datetime.now()
    created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

    booking_param = {
        "sessionid": ObjectId(demosessionid),
        "channelid": ObjectId(demochannelid),
        "status" : "Booked",
        "booked_by" : "demostudent",
        "created_datetime": created_datetime,
        "modified_datetime": created_datetime
    }
    results = mongo.db.bookings.insert_one(booking_param)
    print('Created Booking demobooking (id: %s)' % results.inserted_id)

'''
Main
'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    '''
    For Demo sake
    '''
    demostaff = mongo.db.users.find_one({"username": "demostaff"})
    demostudent = mongo.db.users.find_one({"username": "demostudent"})
    useradmin = mongo.db.users.find_one({"username": "useradmin"})
    demochannel = mongo.db.channels.find_one({"channelname": "Demo Channel"})
    demosession = mongo.db.sessions.find_one()
    demobookings = mongo.db.bookings.find_one()

    # Create Demo Content
    if demostaff is None:
        create_demostaff()
    if demostudent is None:
        create_demostudent()
    if useradmin is None:
        create_useradmin()
    if demochannel is None:
        create_demochannel()
    if demosession is None:
        create_demosession()
    if demobookings is None:
        create_demobooking()

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

                    # Add Audit Logs
                    now = datetime.datetime.now()
                    login_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

                    audit_param = {
                        "type": "Login",
                        "status": "Success",
                        "role": session['role'],
                        "username": username,
                        "login_time": login_datetime
                    }
                    results = mongo.db.audit_logs.insert_one(audit_param)
                    print('Successful login attempt (username: %s)' % session['username'])

                    # Redirect User to Dashboard
                    return redirect(url_for('dashboard'))
            else:
                # Add Audit Logs
                now = datetime.datetime.now()
                login_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

                audit_param = {
                    "type": "Login",
                    "status": "Failed",
                    "role": 'Null',
                    "username": username,
                    "login_time": login_datetime
                }
                results = mongo.db.audit_logs.insert_one(audit_param)
                print('Failed login attempt (username: %s)' % username)

                # Redirect to Login Page
                message = 'Incorrect username or password!'
                alert_type = 'danger'
                return render_template('login.html', message=message, alert_type=alert_type)
        else:
            # Add Audit Logs
            now = datetime.datetime.now()
            login_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

            audit_param = {
                "type": "Login",
                "status": "Failed",
                "role": 'Null',
                "username": 'Null',
                "login_time": login_datetime
            }
            results = mongo.db.audit_logs.insert_one(audit_param)
            print('Failed login attempt (username: <empty>)')

            # Redirect to Login Page
            message = 'Please enter your username and password!'
            alert_type = 'danger'
            return render_template('login.html', message=message, alert_type=alert_type)
    return render_template('login.html')


@app.route('/logout')
def logout():
    # Add Audit Logs
    now = datetime.datetime.now()
    login_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

    userrole = session['role']
    username = session['username']

    audit_param = {
        "type": "Logout",
        "status": "Success",
        "role": session['role'],
        "username": username,
        "login_time": login_datetime
    }
    results = mongo.db.audit_logs.insert_one(audit_param)
    print('Successful Logout attempt (username: %s)' % session['username'])

    '''
    Unset Sessions
    '''
    session.pop('id')
    session.pop('role')
    session.pop('fullname')
    session.pop('username')

    # Redirect to Login Page
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
Bookings
'''
@app.route('/bookings/list')
@auth_required
def list_bookings(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        if session['role'] == 'Student':
            bookings_list = mongo.db.bookings.aggregate([
                {
                  "$match": {
                      "booked_by": session['username']
                  }
                },
                {
                    "$lookup": {
                        "from": "sessions",
                        "localField": "sessionid",
                        "foreignField": "_id",
                        "as": "session_info"
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
            bookings_cursor = mongo.db.bookings.aggregate([
                {
                    "$lookup": {
                        "from": "sessions",
                        "localField": "sessionid",
                        "foreignField": "_id",
                        "as": "session_info"
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
            bookings_list = list(bookings_cursor)

        return render_template('list_bookings.html', message=message, alert_type=alert_type, bookings_list=bookings_list)

@app.route('/booking/create/<sessionid>')
@auth_required
def book_session(sessionid, message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        # check for booked session

        session_details = mongo.db.sessions.find_one({"_id": ObjectId(sessionid)})
        sessionid = session_details['_id']
        username = session['username']
        booking_details = mongo.db.bookings.find_one(
            {
                "sessionid": ObjectId(sessionid),
                "status": "Booked",
                "booked_by": username
            }
        )

        if booking_details is None:
            session_detail = mongo.db.sessions.find_one({"_id": ObjectId(sessionid)})

            now = datetime.datetime.now()
            created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
            booked_by = session['username']

            booking_details = {
                "sessionid": ObjectId(sessionid),
                "channelid": ObjectId(session_detail['channelid']),
                "status": "Booked",
                "booked_by": booked_by,
                "created_datetime": created_datetime,
                "modified_datetime": created_datetime
            }
            results = mongo.db.bookings.insert_one(booking_details)
            message = 'Successfully created booking (booking id: %s)' % results.inserted_id
            alert_type = 'success'
            return redirect(url_for('list_bookings', message=message, alert_type=alert_type))

        else:
            bookingid = booking_details['_id']
            message = 'You have already made a booking! Please select another session! (booking id: %s)' % bookingid
            alert_type = 'danger'
            return redirect(url_for('list_sessions', message=message, alert_type=alert_type))


@app.route('/bookings/cancel/<bookingid>')
@auth_required
def cancel_session(bookingid):
    booking_detail = mongo.db.bookings.find_one({"_id": ObjectId(bookingid)})
    now = datetime.datetime.now()
    modified_datetime = now.strftime("%d/%m/%Y %H:%M:%S")

    booking_id = {
        "_id": ObjectId(bookingid)
    }
    booking_params = {
        "$set": {
            "status": 'Canceled',
            "canceled_by": session['username'],
            "modified_datetime": modified_datetime
        }
    }
    results = mongo.db.bookings.find_one_and_update(booking_id, booking_params)
    message = 'Successfully canceled booking (id: %s)' % results['_id']
    alert_type = 'success'
    return redirect(url_for('list_bookings', message=message, alert_type=alert_type))


'''
Sessions
'''
@app.route('/sessions/create', methods=['GET', 'POST'])
@auth_required
@staff_role_check
def create_session( message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        if request.method == 'POST':
            channelid = request.form.get('channelname')
            sessiondate = request.form.get('sessiondate')
            sessionstarttime = request.form.get('sessionstarttime')
            sessionendtime = request.form.get('sessionendtime')

            if channelid == 'none':
                message = 'Please select an existing channel!'
                alert_type = 'danger'
                return render_template('create_session.html', message=message, alert_type=alert_type)
            if channelid and sessiondate and sessionstarttime and sessionendtime:
                starttime_validation = datetime.datetime.strptime(sessionstarttime, "%H:%M")
                endtime_validation = datetime.datetime.strptime(sessionendtime, "%H:%M")

                if starttime_validation < endtime_validation:
                    channel_detail = mongo.db.channels.find_one(
                        {
                            "_id": ObjectId(channelid)
                        }
                    )
                    channel_start_date = channel_detail['channeldate']
                    channel_end_date = channel_detail['channelenddate']

                    start_date_validation = datetime.datetime.strptime(channel_start_date, "%d/%m/%Y")
                    end_date_validation = datetime.datetime.strptime(channel_end_date, "%d/%m/%Y")
                    session_date_validation = datetime.datetime.strptime(sessiondate, "%d/%m/%Y")

                    # Check whether session date is within channel date range
                    if start_date_validation <= session_date_validation <= end_date_validation:
                        # Save into Database
                        now = datetime.datetime.now()
                        created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
                        created_by = session['username']

                        session_document = {
                            "channelid": ObjectId(channelid),
                            "sessiondate": sessiondate,
                            "sessionstarttime": sessionstarttime,
                            "sessionendtime": sessionendtime,
                            "created_by": created_by,
                            "created_datetime": created_datetime,
                            "modified_datetime": created_datetime
                        }
                        results = mongo.db.sessions.insert_one(session_document)
                        message = 'Successfully created session (id: %s)' % results.inserted_id
                        alert_type = 'success'
                        return redirect(url_for('list_sessions', message=message, alert_type=alert_type))
                    else:
                        message = 'Session Date is not within Channel date range!'
                        alert_type = 'danger'
                        return redirect(url_for('create_session', message=message, alert_type=alert_type))
                else:
                    message = 'Invalid Time Format! (HH:MM)'
                    alert_type = 'danger'
                    return redirect(url_for('create_session', message=message, alert_type=alert_type))

        # check for channels
        channel_count = mongo.db.channels.find().count()

        if channel_count > 0:
            channel_list = mongo.db.channels.find()

            return render_template('create_session.html', message=message, alert_type=alert_type, channel_list=channel_list)
        else:
            message = 'Please create at least 1 channel before creating sessions!'
            alert_type = 'danger'
            return redirect(url_for('create_channel', message=message, alert_type=alert_type))

@app.route('/sessions/list')
@auth_required
def list_sessions(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        if session['role'] == 'Student':
            username = session['username']

            # Only Show Sessions from today onwards
            today_date = datetime.date.today().strftime("%d/%m/%Y")
            search_range = {
                "sessiondate": {
                "$gte": today_date
                }
            }
            sessions_list = mongo.db.sessions.aggregate([
                {
                  "$match": {
                      "sessiondate": {
                            "$gte": today_date
                        }
                  }
                },
                {
                    "$lookup": {
                        "from": "channels",
                        "localField": "channelid",
                        "foreignField": "_id",
                        "as": "channel_info"
                    }
                },
                {
                    "$lookup": {
                        "from": "bookings",
                        "let": {
                            "vars": {"session_id": "$_id" }
                        },
                        "pipeline": [
                            {
                                "$match": {
                                    "booked_by": username,
                                    "canceled_by": {"$exists": False},
                                    "$expr": {
                                        "$eq": ["$bookings.sessionid", "$sessions._id"]
                                    }
                                }
                            }
                        ],
                        "as": "booking_info"
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

        return render_template('list_sessions.html', message=message, alert_type=alert_type, sessions_list=sessions_list)

@app.route('/sessions/edit/<sessionid>', methods=['GET', 'POST'])
@auth_required
@staff_role_check
def edit_session(sessionid, message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        # On POST event
        if request.method == 'POST':
            sessionid = request.form.get('sessionid')
            channelid = request.form.get('channelname')
            sessiondate = request.form.get('sessiondate')
            sessionstarttime = request.form.get('sessionstarttime')
            sessionendtime = request.form.get('sessionendtime')

            if channelid and sessiondate and sessionstarttime and sessionendtime:
                starttime_validation = datetime.datetime.strptime(sessionstarttime, "%H:%M")
                endtime_validation = datetime.datetime.strptime(sessionendtime, "%H:%M")

                if starttime_validation < endtime_validation:
                    channel_detail = mongo.db.channels.find_one(
                        {
                            "_id": ObjectId(channelid)
                        }
                    )
                    channel_start_date = channel_detail['channeldate']
                    channel_end_date = channel_detail['channelenddate']

                    start_date_validation = datetime.datetime.strptime(channel_start_date, "%d/%m/%Y")
                    end_date_validation = datetime.datetime.strptime(channel_end_date, "%d/%m/%Y")
                    session_date_validation = datetime.datetime.strptime(sessiondate, "%d/%m/%Y")

                    # Check whether session date is within channel date range
                    if start_date_validation <= session_date_validation <= end_date_validation:
                        # Save into Database
                        now = datetime.datetime.now()
                        modified_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
                        modified_by = session['username']

                        session_id = {
                            "_id": ObjectId(sessionid)
                        }

                        session_document = {
                            "$set": {
                                "channelid": ObjectId(channelid),
                                "sessiondate": sessiondate,
                                "sessionstarttime": sessionstarttime,
                                "sessionendtime": sessionendtime,
                                "modified_datetime": modified_datetime,
                                "modified_by": modified_by
                            }
                        }
                        results = mongo.db.sessions.find_one_and_update(session_id, session_document)
                        message = 'Successfully edited session (id: %s)' % results['_id']
                        alert_type = 'success'
                        return redirect(url_for('list_sessions', message=message, alert_type=alert_type))
                    else:
                        message = 'Session Date is not within Channel date range!'
                        alert_type = 'danger'
                        return redirect(url_for('edit_session', message=message, alert_type=alert_type))
                else:
                    message = 'Invalid Time Format! (HH:MM)'
                    alert_type = 'danger'
                    return redirect(url_for('edit_session', message=message, alert_type=alert_type))

        # Get Session Details from Database
        session_cursor = mongo.db.sessions.aggregate([
            {
              "$match": {
                  "_id": ObjectId(sessionid)
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

        session_details = list(session_cursor)

        channel_list = mongo.db.channels.find()

        return render_template('edit_session.html', message=message, alert_type=alert_type, session_details=session_details, channel_list=channel_list)

@app.route('/sessions/delete/<sessionid>', methods=['GET', 'POST'])
@auth_required
@staff_role_check
def delete_session(sessionid, message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        # On POST event
        if request.method == 'POST':
            sessionid = request.form.get('sessionid')

            if sessionid:
                session_id = {
                    "_id": ObjectId(sessionid)
                }

                results = mongo.db.sessions.find_one_and_delete(session_id)
                message = 'Successfully deleted session (id: %s)' % results['_id']
                alert_type = 'success'
                return redirect(url_for('list_sessions', message=message, alert_type=alert_type))

        # Get Session Details from Database
        session_cursor = mongo.db.sessions.aggregate([
            {
              "$match": {
                  "_id": ObjectId(sessionid)
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

        session_details = list(session_cursor)

        channel_list = mongo.db.channels.find()

        return render_template('delete_session.html', message=message, alert_type=alert_type, session_details=session_details, channel_list=channel_list)

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
                "channelenddate": {
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
@staff_role_check
def create_channel(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        if request.method == 'POST':
            channelname = request.form.get('channelname')
            channeldate = request.form.get('channeldate')
            channelenddate = request.form.get('channelenddate')
            # starttime = request.form.get('starttime')
            # endtime = request.form.get('endtime')
            capacity = int(request.form.get('capacity'))

            if channelname and channeldate and channelenddate and capacity:
                try:
                    date_validation = datetime.datetime.strptime(channeldate, "%d/%m/%Y")
                    enddate_validation = datetime.datetime.strptime(channelenddate, "%d/%m/%Y")
                    # starttime_validation = datetime.datetime.strptime(starttime, "%H%M")
                    # endtime_validation = datetime.datetime.strptime(endtime, "%H%M")
                except ValueError:
                    message = 'Invalid Date/Time Format! (dd/mm/yy, HHHH)'
                    alert_type = 'danger'
                    return redirect(url_for('create_channel', message=message, alert_type=alert_type))

                if (date_validation < enddate_validation):
                    if (isinstance(capacity, int) and (capacity > 0)):
                        now = datetime.datetime.now()
                        created_datetime = now.strftime("%d/%m/%Y %H:%M:%S")
                        created_by = session['username']

                        channel = {
                            "channelname": channelname,
                            "channeldate": channeldate,
                            "channelenddate": channelenddate,
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
                    message = 'Invalid Start and End Date'
                    alert_type = 'danger'
                    return redirect(url_for('create_channel', message=message, alert_type=alert_type))
            else:
                message = "Please fill in all the fields!"
                alert_type = 'danger'
        return render_template('create_channel.html', message=message, alert_type=alert_type)

@app.route('/channels/edit/<channelid>', methods=['GET', 'POST'])
@auth_required
@staff_role_check
def edit_channel(channelid, message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        channel_details = mongo.db.channels.find_one({"_id": ObjectId(channelid)})

        if request.method == 'POST':
            channelname = request.form.get('channelname')
            channeldate = request.form.get('channeldate')
            channelenddate = request.form.get('channelenddate')
            # starttime = request.form.get('starttime')
            # endtime = request.form.get('endtime')
            capacity = int(request.form.get('capacity'))

            if channelname and channeldate and channelenddate and capacity:
                try:
                    date_validation = datetime.datetime.strptime(channeldate, "%d/%m/%Y")
                    enddate_validation = datetime.datetime.strptime(channelenddate, "%d/%m/%Y")
                    # starttime_validation = datetime.datetime.strptime(starttime, "%H%M")
                    # endtime_validation = datetime.datetime.strptime(endtime, "%H%M")
                except ValueError:
                    message = 'Invalid Date/Time Format! (dd/mm/yy, HHHH)'
                    alert_type = 'danger'
                    return redirect(url_for('create_channel', message=message, alert_type=alert_type))

                # if (channeldate > channelenddate):
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
                            "channelenddate": channelenddate,
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
                # else:
                #     message = 'Invalid Start and End Date'
                #     alert_type = 'danger'
                #     return redirect(url_for('edit_channel', message=message, alert_type=alert_type))
            else:
                message = "Please fill in all the fields!"
                alert_type = 'danger'
        return render_template('edit_channel.html', message=message, alert_type=alert_type, channel=channel_details)


@app.route('/channels/delete/<channelid>', methods=['GET', 'POST'])
@auth_required
@staff_role_check
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

@app.route('/audit/list')
@auth_required
@admin_role_check
def view_audit_logs(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        audit_logs = mongo.db.audit_logs.find()
        return render_template('list_audit_logs.html', message=message, alert_type=alert_type, audit_logs=audit_logs)


'''
Users
'''

@app.route('/users/list')
@auth_required
@admin_role_check
def list_users(message='', alert_type=''):
        if request.args.get('message') and request.args.get('alert_type'):
            message = request.args.get('message')
            alert_type = request.args.get('alert_type')

        users_list = mongo.db.users.find()
        return render_template('list_users.html', message=message, alert_type=alert_type, users_list=users_list)

@app.route('/users/create', methods=['GET', 'POST'])
@auth_required
@admin_role_check
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
@admin_role_check
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
@admin_role_check
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