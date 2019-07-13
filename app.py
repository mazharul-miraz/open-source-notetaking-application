from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient

mongoConnect = MongoClient()
client = MongoClient('localhost', 27017)
db = client.todo_app

print(db)

from flask import Flask
app = Flask(__name__)


@app.route("/")
def approot():
    return  render_template('index.html')

@app.route("/login", methods =['POST','GET'])
def login():
    if request.method == 'POST':
    	return request.form['username']
    else:
    	return render_template('auth_login.html')

@app.route("/reg", methods =['POST','GET'])
def reg():
    if request.method == 'POST':
        return userRegistration(request)
    else:
	    return render_template('reg.html')

def userRegistration(request):
    uName = request.form['username']
    uPass = request.form['password']
    return uName;


if __name__ == "__main__":
	app.run(debug=True)
