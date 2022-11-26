from flask import Flask, render_template, request, make_response
import sqlite3
import tools

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

@app.route("/browse")
def browse():
    return "Not implemented yet"


if __name__ == "__main__":
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
    sql.execute("CREATE TABLE notes (id INT PRIMARY KEY, username nvarchar(100), note nvarchar(256), privacy nvarchar(10));")
    sql.execute("DELETE FROM notes;")
    sql.execute("INSERT INTO notes (username, note, id) VALUES ('bob', 'To jest sekret!', 1);")
    db.commit()

    app.run("0.0.0.0", 5000)