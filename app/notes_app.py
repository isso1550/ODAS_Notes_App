from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import os
import glob
import requests
import filetype
import sqlite3
import tools
import markdown
import notecrypt
import jwtbuilder

DB_FILE = "./notesapp.db"
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_SUSPENSION_TIME = timedelta(minutes=15)

TEMP_SAVE_FOLDER = "./user_pictures/temp"
AVATAR_SAVE_FOLDER = "./user_pictures/avatars"
NOTEPIC_SAVE_FOLDER = "./user_pictures/notepics"
FILE_ALLOWED_EXTENSIONS = ['png','jpg','jpeg','gif']
FILE_MAX_SIZE = 8* 1024 * 1024

login_manager = LoginManager()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024 #8mb
app.secret_key = "abdabdabababababasbasbsabs"
login_manager.init_app(app)
#login_manager.login_view = 'login'

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    sql.execute("SELECT username, email, password FROM users WHERE username = :username", {"username":username})
    try:
        username, email, password = sql.fetchone()
    except:
        return None
    user = User()
    user.id = username
    user.email = email
    user.password = password
    return user

    

@app.route("/")
def welcome():
    print(request.headers.get('Host'))
    return render_template("welcome.html")
@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")

@app.route("/register")
def register():
    return render_template("register.html")
@app.route("/register", methods = ['POST'])
def registerUser():
    #!!!!!!!!!!!!!!!!!!!!!!!! TODO weryfikacja danych od uzytkownika!!!!!!!!!!!!!!!!!!!!!!!!1
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirm-password")

    if password != confirmation:
        return "Passwords do not match!", 409
    #!!!!!!!!!!!!!!!!!!!!!!!!TODO entropia hasła!!!!!!!!!!!!!!!!!!!
    #!!!!!!!!!!!!!!!!!!!!!!!!TODO sprawdzanie czy uzytkownik probowal sql injection!!!!!!!!!!!!!!!!!!!!!
    hash = tools.registerHash(password)
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    db_user = sql.execute("SELECT * FROM users WHERE username=:username", {"username":username}).fetchone()
    if(db_user == None):
        sql.execute("INSERT INTO users (email, username, password) VALUES (:email, :username, :password)", {"email":email, "username":username, "password": hash})
        db.commit()
        print("Registered user " + username)
        return "Registration successful"
    return "Username already in use"

@app.route("/login")
def login():
    return render_template("login.html")
@app.route("/login", methods = ['POST'])
def loginUser():
    email = request.form.get("email")
    password = request.form.get("password")
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    '''
    login_attempts = sql.execute("SELECT * FROM login_attempts WHERE email = :email", {"email":email}).fetchall()
    if(login_attempts != None):
        #Usuwanie przestarzałych prób logowania
        yesterday = (datetime.utcnow() - ACCOUNT_SUSPENSION_TIME).strftime("%Y-%m-%d %H:%M:%S")
        sql.execute("DELETE FROM login_attempts WHERE email = :email AND date < (:yesterday)", {"email":email, "yesterday":yesterday})
        db.commit()
        login_attempts = sql.execute("SELECT * FROM login_attempts WHERE email = :email", {"email":email}).fetchall()
        if(login_attempts != None):
            if (len(login_attempts)==MAX_LOGIN_ATTEMPTS):
                return "Account temporarily blocked for too many failed logins"
                #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!TODO wyslij link do zmiany hasla !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    '''
    db_hash = sql.execute("SELECT password FROM users WHERE email = :email", {"email":email}).fetchone()
    #print(db_hash)
    if (db_hash != None):
        db_hash = db_hash[0]
        hash = tools.loginHash(password, db_hash)
        if (hash == db_hash):
            #Logowanie użytkownika - można usunąć wszystkie nieudane próby z bazy
            #sql.execute("DELETE FROM login_attempts WHERE email = :email", {"email":email})
            #db.commit()

            username = sql.execute("SELECT username from users WHERE email=:email", {"email":email}).fetchone()[0]
            user = user_loader(username)
            login_user(user)

            return redirect('/mynotes')
            return "Logged in as " + email
    #Nieudane logowanie - zapisanie próby i zwrócenie błędu
    sql.execute("INSERT INTO login_attempts (ip, email, date) VALUES (:ip, :email, CURRENT_TIMESTAMP)", {"ip":request.remote_addr, "email":email})
    db.commit()
    return "Incorrect email or password", 401

@app.route("/create")
@login_required
def createNote():
    return render_template("createNote.html")


@app.route("/create", methods = ['POST'])
@login_required
def saveNewNote():
    username = current_user.id
    #!!!!!!!!!!!!!!!!!!!!!!!!TODO GET USERNAME!!!!!!!!!!!!!!!!!!!!!!
    title = request.form.get("title")
    picture_url = request.form.get('picture')
    privacy = request.form.get("privacy")
    note = request.form.get("note")
    
    #privacy
    if(privacy not in ["private","unlisted","public"]):
        print(privacy)
        #!!!!!!!!!!!!!!!!!!!!!!!!!TODO log suspicious action!!!!!!!!!!!!!!!!!!!!!!!!!!
        return "Suspicious action logged"
    if(privacy == "private"):
        title = notecrypt.encrypt_note(title)
        note = notecrypt.encrypt_note(note)
        print("Remember to crypt!")
    #title
    if(title == ""):
        title = "Untitled"
    
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    #!!!!!!!!!!!!!!!!!!!TODO sprawdzenie czy uzytkownik probowal sqlnjection!!!!!!!!!!!!!!!!!!!!
    sql.execute("INSERT INTO notes (username, title, privacy, note) VALUES (:username, :title, :privacy, :note)", {"username":username, "title": title, "privacy": privacy, "note": note})
    db.commit()
    recent_id = sql.lastrowid

    #pic
    #!!!!!!!!!!!!!!!!!!!!!!!TODO upewnic sie testami ze jest ok !!!!!!!!!!!!!!!!!!!!!!!!
    try:
        response = requests.get(picture_url)
        if (len(response.content) > FILE_MAX_SIZE):
            return redirect("/render/" + str(recent_id))

        temp_filepath = TEMP_SAVE_FOLDER + str(recent_id) + ".png"
        open(temp_filepath, "wb").write(response.content)
        kind = filetype.guess(temp_filepath)
        if kind is None:
            #_________________________________________________________LOG SUSPICIOUS
            return "File invalid", 400
        os.remove(temp_filepath)
        if kind.extension in FILE_ALLOWED_EXTENSIONS:
            #Usuwa stare (zeby nie bylo wielu zdjec z roznymi rozszerzeniami dla jednego uzytkownika)
            pics = glob.glob(NOTEPIC_SAVE_FOLDER + "/" + str(recent_id) + ".*")
            for pic in pics:
                os.remove(pic)
            filename = "/"+ str(recent_id) + "." + str(kind.extension)
            filepath = os.path.join(NOTEPIC_SAVE_FOLDER + filename)
            open(filepath, 'wb').write(response.content)
            
        else:
            return "Unallowed filetype", 400
    except Exception as e:
        print(e)
        return "Incorrect URL", 400


    return redirect("/render/" + str(recent_id))

@app.route("/render/<id>")
def renderNote(id):
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    try:
        author, title, privacy, note = sql.execute("SELECT username, title, privacy, note FROM notes WHERE id = :id", {"id":id}).fetchone()
    except:
        return redirect("/")
    if (privacy == "private"):
        if not (current_user.is_authenticated):
            return "Login to browse private notes!"
        username = current_user.id
        if (username != author):
            return "You are not the author!"
        title = notecrypt.decrypt_note(title)
        note = notecrypt.decrypt_note(note)
        1==1
    note = markdown.markdown(note)
    #tekst wybielony przed wyswietleniem
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!TODO wyswietlanie zdjec!!!!!!!!!!!!!!!!!!!!!!!
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!TODO poprawic render.html template!!!!!!!!!!!!!
    note = tools.cleanText(note)
    return render_template("render.html", note=note)


@app.route("/browse")
def browse():
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    public_notes = sql.execute("SELECT id, title, username FROM notes WHERE privacy = 'public'").fetchall()
    return render_template("browse.html", public_notes=public_notes)

@app.route("/mynotes")
@login_required
def mynotes():
    username = current_user.id
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    private_notes = sql.execute("SELECT id, title, username FROM notes WHERE username = :username", {"username":username}).fetchall()
    return render_template("browse.html",  public_notes=private_notes)


@app.route("/resetPassword")
def resetpassword():
    args = request.args
    if(args.get("token") is not None):
        return render_template("newPassword.html")
    return render_template("resetPassword.html")
@app.route("/resetPassword", methods = ['POST'])
def sendResetEmail():
    email = request.form.get("email")
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    try:
        sql.execute("SELECT username, email, password FROM users WHERE email = :email", {"email":email})
        row = sql.fetchone()
        username, email, password = row
    except:
        return redirect("/")
    print("Prośba zmiany hasła")
    print(username, email, password)
    token = jwtbuilder.buildUserDataJWT(row)
    return ("Sending email... %s %s" % (email, "http://127.0.0.1:5000/resetPassword?token="+token))

@app.route("/updatePassword", methods = ['POST'])
def saveNewPassword():
    password = request.form.get('password')
    token = request.form.get('token')
    print(token)
    data = jwtbuilder.decodeUserDataJWT(token)
    if (data == 1):
        return "Token invalid"
    username = data['payload'][0]
    email = data['payload'][1]
    hash = tools.registerHash(password)
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    sql.execute("UPDATE users SET password=:password WHERE username=:username AND email=:email", {"password":hash, "username":username, "email":email})
    db.commit()
    return "Success"

@app.route("/me")
@login_required
def myData():
    username = current_user.id
    return render_template("me.html", username=username)

@app.route("/updateAvatar", methods=['POST'])
@login_required
def updateAvatar():
    if 'file' not in request.files:
        return redirect("/me")
    file = request.files['file']
    if file.filename == "":
        return redirect("/me")
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    try:
        id = sql.execute("SELECT id FROM users WHERE username=:username", {"username": current_user.id}).fetchone()[0]
        temp_filepath = os.path.join(TEMP_SAVE_FOLDER  + str(id)+".png")
        file.save(temp_filepath)
        kind = filetype.guess(temp_filepath)
        if kind is None:
            #_________________________________________________________LOG SUSPICIOUS
            return "File invalid", 400
        os.remove(temp_filepath)
        if kind.extension in FILE_ALLOWED_EXTENSIONS:
            #Usuwa stare (zeby nie bylo wielu zdjec z roznymi rozszerzeniami dla jednego uzytkownika)
            pics = glob.glob(AVATAR_SAVE_FOLDER + "/" + str(id) + ".*")
            for pic in pics:
                os.remove(pic)
            filename = "/"+ str(id) + "." + str(kind.extension)
            filepath = os.path.join(AVATAR_SAVE_FOLDER + filename)
            file.stream.seek(0)
            file.save(os.path.join(filepath))
        else:
            return "Unallowed filetype", 400

    except:
        return redirect("/me")
    return redirect("/me")

@app.route("/getAvatar")
@login_required
def getAvatar():
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    try:
        id = sql.execute("SELECT id FROM users WHERE username=:username", {"username": current_user.id}).fetchone()[0]
        pics = glob.glob(AVATAR_SAVE_FOLDER + "/" + str(id) + ".*")
        if len(pics) > 0:
            return send_file(pics[0])
        else: return send_file(AVATAR_SAVE_FOLDER + "/default.png")
    except Exception as e:
        print(e)
        return send_file(AVATAR_SAVE_FOLDER + "/default.png")

@app.route("/getNotePicture/<id>")
def getNotePicture(id):
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    try:
        author, privacy= sql.execute("SELECT username, privacy FROM notes WHERE id = :id", {"id":id}).fetchone()
    except:
        return redirect("/")
    if (privacy == "private"):
        if not (current_user.is_authenticated):
            return "Login to browse private notes!"
        username = current_user.id
        if (username != author):
            return "You are not the author!"
        
    pics = glob.glob(NOTEPIC_SAVE_FOLDER + "/" + str(id) + ".*")
    if len(pics) > 0:
        return send_file(pics[0])
    return send_file(NOTEPIC_SAVE_FOLDER + "/default.png")

if __name__ == "__main__":
    INIT_DB = False
    INIT_USER_FILES = False
    if (INIT_DB):
        print("[*] Init database!")
        db = sqlite3.connect(DB_FILE)
        sql = db.cursor()
        sql.execute("DROP TABLE IF EXISTS users;")
        sql.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email varchar(100), username varchar(100), password varchar(128));")
        sql.execute("DELETE FROM users;")

        sql.execute("DROP TABLE IF EXISTS login_attempts;")
        sql.execute("CREATE TABLE login_attempts (ip varchar(12), email varchar(100), date datetime)")
        sql.execute("DELETE FROM login_attempts")

        sql.execute("DROP TABLE IF EXISTS notes;")
        sql.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, username varchar(100), title varchar(100), privacy varchar(10), note varchar(256));")
        sql.execute("DELETE FROM notes;")
        sql.execute("INSERT INTO notes (username, note, id) VALUES ('bob', 'To jest sekret!', 1);")
        db.commit()

    if (INIT_USER_FILES):
        print("[*] Init user files! Deleting all except defaults...")
        all = glob.glob(AVATAR_SAVE_FOLDER + "/*")
        all.remove(glob.glob(AVATAR_SAVE_FOLDER + "/default*")[0])
        for file in all:
            os.remove(file)
        all = glob.glob(NOTEPIC_SAVE_FOLDER + "/*")
        all.remove(glob.glob(NOTEPIC_SAVE_FOLDER + "/default*")[0])
        for file in all:
            os.remove(file)
    app.run("0.0.0.0", 5000)