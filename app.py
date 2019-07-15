from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
import bcrypt
import jwt
import config as config

mongoConnect = MongoClient()
client = MongoClient('localhost', 27017)
db = client.todo_app

#try:
#    db.user.insert_one({
#        "name": "Miraz",
#         "password": "123"
#         })
# except Exception as e:
#         print(e)

from flask import Flask
app = Flask(__name__)


@app.route("/")
def approot():
    return  render_template('index.html')

@app.route("/admin")
def admin():
    return  render_template('admin.html')



@app.route("/login", methods =['POST','GET'])
def login():
    if request.method == 'POST':
        return userLogin(request)
    else:
        return render_template('login.html')



@app.route("/reg", methods =['POST','GET'])
def reg():
    if request.method == 'POST':
        return userRegistration(request)
    else:
	    return render_template('reg.html')

@app.route("/userdash")
def userdash():

    name = request.cookies.get('token')

    if name == None :
        return redirect(url_for('login' ))
    else:
        try:
            greenpass = jwt.decode(name.encode('utf-8'), config.data["JWT_SECRET"], algorithms=['HS256'])
            return  render_template('userdash.html')
        except Exception as e:
            resp = redirect(url_for('login'))
            resp.set_cookie('token', '')
            return resp




def userLogin(request):
    uEmail = request.form['emailid']
    uPass = request.form['password']

    isUserExist = db.user.find_one({
        "email": uEmail
    })

    if isUserExist == None:
        return "Please register"
    else:
        if bcrypt.checkpw(uPass.encode('utf-8'), isUserExist['password']):
            encoded_jwt = jwt.encode({
                'name': isUserExist['name'],
                'email': isUserExist['email']
            }, config.data["JWT_SECRET"], algorithm='HS256')
            resp = redirect(url_for('userdash', message='' ))
            resp.set_cookie('token', encoded_jwt)
            return resp
        else:
            return "Password didn't match"

def userRegistration(request):
    uName = request.form['name']
    uEmail = request.form['emailid']
    uPass = request.form['password']
    uPass = bcrypt.hashpw(uPass.encode('utf-8'), bcrypt.gensalt())

    isUserExist = db.user.find_one({
        "email": uEmail
    })

    if isUserExist != None:
        print(isUserExist)
        return "User already exist"
    else:
        db.user.insert_one({
            "name": uName,
            "email": uEmail,
            "password": uPass
        })
        # return "Registration successfull"
        return  render_template('userdash.html')

    print(isUserExist)

    return uPass;

if __name__ == "__main__":
	app.run(debug=True)
