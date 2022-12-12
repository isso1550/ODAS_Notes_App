from datetime import datetime, timedelta
from flask import Flask, render_template, request, make_response, redirect, flash
import sqlite3
import tools
import markdown
import notecrypt

DB_FILE = "./notesapp.db"
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_SUSPENSION_TIME = timedelta(minutes=15)

app = Flask(__name__)


@app.route("/")
def welcome():
    print(request.headers.get('Host'))
    return render_template("welcome.html")

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
    #Można o tym poinformować, bo zakładamy że znajomość nazwy użytkownika nie da atakującemu dostępu do konta
    return "Username already in use"

@app.route("/login")
def login():
    return render_template("login.html")
@app.route("/login", methods = ['POST'])
def loginUser():
    username = request.form.get("username")
    password = request.form.get("password")
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    login_attempts = sql.execute("SELECT * FROM login_attempts WHERE username = :username", {"username":username}).fetchall()
    if(login_attempts != None):
        #Usuwanie przestarzałych prób logowania
        yesterday = (datetime.utcnow() - ACCOUNT_SUSPENSION_TIME).strftime("%Y-%m-%d %H:%M:%S")
        sql.execute("DELETE FROM login_attempts WHERE username = :username AND date < (:yesterday)", {"username":username, "yesterday":yesterday})
        db.commit()
        login_attempts = sql.execute("SELECT * FROM login_attempts WHERE username = :username", {"username":username}).fetchall()
        if(login_attempts != None):
            if (len(login_attempts)==MAX_LOGIN_ATTEMPTS):
                return "Account temporarily blocked for too many failed logins"
                #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!TODO wyslij link do zmiany hasla !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    db_hash = sql.execute("SELECT username, password FROM users WHERE username = :username", {"username":username}).fetchone()[1]
    hash = tools.loginHash(password, db_hash)
    if (hash == db_hash):
        #Logowanie użytkownika - można usunąć wszystkie nieudane próby z bazy
        sql.execute("DELETE FROM login_attempts WHERE username = :username", {"username":username})
        db.commit()
        return "Logged in as " + username
    #Nieudane logowanie - zapisanie próby i zwrócenie błędu
    sql.execute("INSERT INTO login_attempts (ip, username, date) VALUES (:ip, :username, CURRENT_TIMESTAMP)", {"ip":request.remote_addr, "username":username})
    db.commit()
    return "Incorrect username or password", 401

@app.route("/create")
def createNote():
    return render_template("createNote.html")
@app.route("/create", methods = ['POST'])
def saveNewNote():
    username = "bob"
    #!!!!!!!!!!!!!!!!!!!!!!!!TODO GET USERNAME!!!!!!!!!!!!!!!!!!!!!!
    title = request.form.get("title")
    privacy = request.form.get("privacy")
    note = request.form.get("note")
    
    if(privacy not in ["private","unlisted","public"]):
        print(privacy)
        #!!!!!!!!!!!!!!!!!!!!!!!!!TODO log suspicious action!!!!!!!!!!!!!!!!!!!!!!!!!!
        return "Suspicious action logged"
    if(privacy == "private"):
        title = notecrypt.encrypt_note(title)
        note = notecrypt.encrypt_note(note)
        print("Remember to crypt!")
    if(title == ""):
        title = "Untitled"
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    #!!!!!!!!!!!!!!!!!!!TODO sprawdzenie czy uzytkownik probowal sqlnjection!!!!!!!!!!!!!!!!!!!!
    sql.execute("INSERT INTO notes (username, title, privacy, note) VALUES (:username, :title, :privacy, :note)", {"username":username, "title": title, "privacy": privacy, "note": note})
    db.commit()
    recent_id = sql.lastrowid
    return redirect("/render/" + str(recent_id))

@app.route("/render/<id>")
def renderNote(id):
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    title, privacy, note = sql.execute("SELECT title, privacy, note FROM notes WHERE id = :id", {"id":id}).fetchone()
    if (privacy == "private"):
        #!!!!!!!!!!!!!!!!!!!!!!!!!TODO verify user login!!!!!!!!!!!!!!!!!!!!!
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
    print(public_notes)
    print(public_notes[0][0])
    return render_template("browse.html", public_notes=public_notes)


if __name__ == "__main__":
    INIT_DB = False
    if (INIT_DB):
        print("[*] Init database!")
        db = sqlite3.connect(DB_FILE)
        sql = db.cursor()
        sql.execute("DROP TABLE IF EXISTS users;")
        sql.execute("CREATE TABLE users (email varchar(100), username varchar(100), password varchar(128));")
        sql.execute("DELETE FROM users;")

        sql.execute("DROP TABLE IF EXISTS login_attempts;")
        sql.execute("CREATE TABLE login_attempts (ip varchar(12), username varchar(100), date datetime)")
        sql.execute("DELETE FROM login_attempts")

        sql.execute("DROP TABLE IF EXISTS notes;")
        sql.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, username varchar(100), title varchar(100), privacy varchar(10), note varchar(256));")
        sql.execute("DELETE FROM notes;")
        sql.execute("INSERT INTO notes (username, note, id) VALUES ('bob', 'To jest sekret!', 1);")
        db.commit()

    app.run("0.0.0.0", 5000)