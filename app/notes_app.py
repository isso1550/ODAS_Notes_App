from flask import Flask, render_template, request, make_response, redirect
import sqlite3
import tools
import markdown

DB_FILE = "./notesapp.db"

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
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirm-password")

    if password != confirmation:
        return "Passwords do not match!", 409
    #!!!!!!!!!!!!!!!!!!!!!!!!TODO co jesli user w bazie?!!!!!!!!!!!!!!!!!!!!!
    #!!!!!!!!!!!!!!!!!!!!!!!!TODO entropia hasła!!!!!!!!!!!!!!!!!!!
    #!!!!!!!!!!!!!!!!!!!!!!!!TODO sprawdzanie czy uzytkownik probowal sql injection!!!!!!!!!!!!!!!!!!!!!
    hash = tools.registerHash(password)
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    sql.execute("INSERT INTO users (username, password) VALUES (:username, :password)", {"username":username, "password": hash})
    db.commit()
    return "Not implemented yet"

@app.route("/login")
def login():
    return render_template("login.html")
@app.route("/login", methods = ['POST'])
def loginUser():
    username = request.form.get("username")
    password = request.form.get("password")
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    db_hash = sql.execute("SELECT username, password FROM users WHERE username = :username", {"username":username}).fetchone()[1]
    hash = tools.loginHash(password, db_hash)
    if (hash == db_hash):
        #LOGIN
        return "Logged in as " + username
    return "Not implemented yet"

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
        #!!!!!!!!!!!!!!!!!!!!!!!!!TODO crypt note!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        print("Remember to crypt!")
    if(title == ""):
        title = "Untitled"
    print(title, privacy, note)
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
    return "Not implemented yet"


if __name__ == "__main__":
    INIT_DB = False
    if (INIT_DB):
        print("[*] Init database!")
        db = sqlite3.connect(DB_FILE)
        sql = db.cursor()
        sql.execute("DROP TABLE IF EXISTS users;")
        sql.execute("CREATE TABLE users (username varchar(100), password varchar(128));")
        sql.execute("DELETE FROM users;")
        #sql.execute("INSERT INTO users (username, password) VALUES ('bach', '$5$rounds=535000$ZJ4umOqZwQkWULPh$LwyaABcGgVyOvJwualNZ5/qM4XcxxPpkm9TKh4Zm4w4');")
        #sql.execute("INSERT INTO users (username, password) VALUES ('john', '$5$rounds=535000$AO6WA6YC49CefLFE$dsxygCJDnLn5QNH/V8OBr1/aEjj22ls5zel8gUh4fw9');")
        #sql.execute("INSERT INTO users (username, password) VALUES ('bob', '$5$rounds=535000$.ROSR8G85oGIbzaj$u653w8l1TjlIj4nQkkt3sMYRF7NAhUJ/ZMTdSPyH737');")

        sql.execute("DROP TABLE IF EXISTS notes;")
        sql.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, username varchar(100), title varchar(100), privacy varchar(10), note varchar(256));")
        sql.execute("DELETE FROM notes;")
        sql.execute("INSERT INTO notes (username, note, id) VALUES ('bob', 'To jest sekret!', 1);")
        db.commit()

    app.run("0.0.0.0", 5000)