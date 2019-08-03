from flask import Flask, render_template, url_for, request, redirect , send_from_directory
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
import bcrypt
import jwt
import config as config
from bson.objectid import ObjectId

mongoConnect = MongoClient()
client = MongoClient('localhost', 27017)
db = client.todo_app

from flask import Flask
app = Flask(__name__)


@app.route("/")
def approot():
    return  render_template('app-view.html')

@app.route("/admin")
def admin():
    return  render_template('app-admin.html')

@app.route("/login", methods =['POST','GET'])
def login():
    if request.method == 'POST':
        return userLogin(request)
    else:
        return render_template('app-login.html')

@app.route("/register", methods =['POST','GET'])
def reg():
    if request.method == 'POST':
        return userRegistration(request)
    else:
	    return render_template('app-reg.html')

@app.route("/signout", methods =['POST','GET'])
def signout():
    resp = redirect(url_for('login'))
    resp.set_cookie('token', '')
    return resp

@app.route("/delnote", methods =['POST','GET'])
def delnote():

    noteId = request.args.get("id")
    token = request.cookies.get('token')

    if token == None :
        return redirect(url_for('login' ))

    else:
        try:
            userData = jwt.decode(token.encode('utf-8'), config.data["JWT_SECRET"], algorithms=['HS256'])
            user_name =  userData['name']
            user_email =  userData['email']

            curNote = db.notes.find_one({
                "_id": ObjectId(noteId)
            })
            print(curNote['email'])
            print(user_email)

            if curNote['email'] == user_email :
                db.notes.delete_one({ "_id": ObjectId(noteId) })
                return redirect("/dashboard")
            else:
                return redirect("/dashboard")
        except Exception as e:
            print(e)
            return redirect("/dashboard")

@app.route("/share", methods =['POST','GET'])
def share():
    if request.method == 'POST':     
        noteId = request.args.get("id")
        email = request.args.get("email")
        isUserExist = db.user.find_one({"email": email})

        if isUserExist != None:
            return render_template('share.html', user_not_exist = true)
        else:
            db.notes.update_one({ 
                "_id": ObjectId(noteId)
                }, {
                    "$set": { 
                        "address": "Canyon 123"
                        }
                })
    else:
        noteId = request.args.get("id")
        token = request.cookies.get('token')
    
        if noteId == None :
            return redirect(url_for('login'))
        elif token == None :
            return redirect(url_for('login'))
        else :
            try:
                userData = jwt.decode(token.encode('utf-8'), config.data["JWT_SECRET"], algorithms=['HS256'])
                user_name =  userData['name']
                user_email =  userData['email']

                curNote = db.notes.find_one({
                "_id": ObjectId(noteId)
                })
                return render_template('share.html', userrrrr_name = user_name, note = curNote)
            except Exception as e:
                print(e)
                return redirect("/dashboard")



@app.route("/dashboard", methods = ['GET','POST'])
def dashboard():

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
                return redirect("/dashboard")
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

                return  render_template('dashboard.html', userrrrr_name = user_name, notes = note_list)
            except Exception as e:
                print(e)
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
            resp = redirect(url_for('dashboard' ))
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
        # return  render_template('userdash.html')
        return redirect(url_for('dashboard' ))

    print(isUserExist)

    return uPass;

if __name__ == "__main__":
	app.run(debug=True)

