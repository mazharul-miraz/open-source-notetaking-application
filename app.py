from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
import bcrypt
import jwt
import config as config

mongoConnect = MongoClient()
client = MongoClient('localhost', 27017)
db = client.todo_app

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







#   USER DASH START   #


@app.route("/userdash", methods = ['GET','POST'])
def userdash():

    if request.method == 'POST':

        token = request.cookies.get('token')
        if token == None :
            return redirect(url_for('login' ))

        else:
            try:
                greenpass = jwt.decode(token.encode('utf-8'), config.data["JWT_SECRET"], algorithms=['HS256'])
                user_email =  greenpass['email']
                note_title = request.form['note']
                note_data =  request.form['message']
                db.notes.insert_one({
                    "note": note_title,
                    "message":note_data,
                    "email": user_email
                })

                user_notes = db.notes.find({
                        "email": user_email,
                    })
                return redirect("/userdash")
                # return 'its okay'

            except Exception as e:
                print(e)
                resp = redirect(url_for('login'))
                resp.set_cookie('token', '')
                return resp
    else:
        token = request.cookies.get('token')
        if token == None :
            return redirect(url_for('login' ))
        else:
            try:
                greenpass = jwt.decode(token.encode('utf-8'), config.data["JWT_SECRET"], algorithms=['HS256'])
                user_name =  greenpass['name']
                user_email =  greenpass['email']

                UserNotes = db.notes.find({
                    "email": user_email
                })

                note_list = []

                for x in UserNotes:
                    note_list.append(x)

                # print(UserNotes)

                return  render_template('userdash.html', userrrrr_name = user_name, notes = note_list)
            except Exception as e:
                print(e)
                resp = redirect(url_for('login'))
                resp.set_cookie('token', '')
                return resp



#   USER DASH START   #








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
            resp = redirect(url_for('userdash' ))
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
