from flask import Flask, request
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/cityboys"

mongo = PyMongo(app)

@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/api/staffs')
def staffs():
    if request.method == 'GET':
        staffs_list = mongo.db.staffs.find()
        for staff in staffs_list:
            print (staff)
        return 'tessst'


if __name__ == '__main__':
    app.run(debug=True)
