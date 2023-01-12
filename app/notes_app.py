from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, send_file, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from dotenv import load_dotenv
import os
import re
import base64
import glob
import requests
import time
import filetype
import sqlite3
import tools
import markdown
import notecrypt
import jwtbuilder
import login_ban_handler
from logger import Logger

load_dotenv()

DB_FILE = "./notesapp.db"
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_SUSPENSION_TIME = timedelta(minutes=15)
HASH_DELAY = 0.5

TEMP_SAVE_FOLDER = "./user_pictures/temp"
AVATAR_SAVE_FOLDER = "./user_pictures/avatars"
NOTEPIC_SAVE_FOLDER = "./user_pictures/notepics"
FILE_ALLOWED_EXTENSIONS = ['png','jpg','jpeg','gif']
FILE_MAX_SIZE = 8* 1024 * 1024

APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
print(APP_SECRET_KEY)

login_manager = LoginManager()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024 #8mb
app.secret_key = APP_SECRET_KEY
login_manager.init_app(app)
#login_manager.login_view = 'login'

logger = Logger()

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
    #Proste odesłanie strony powitalnej
    return render_template("welcome.html")
@app.route("/logout")
def logout():
    #Proste wylogowanie
    logout_user()
    return redirect("/")

@app.route("/register")
def register():
    return render_template("register.html")
@app.route("/register", methods = ['POST'])
def registerUser():
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirm-password")
    #Weryfikacja poprawnosci nazwy uzytkownika
        #user_re = r'^[a-zA-z1-9!"#$%&\'()*+.\-\/:;<=>?@[\\\]^_`{|}~]*$'
        #if not (re.match(user_re, username)):
    for arg in [email, username, password, confirmation]:
        if (len(arg) < 1):
            return "Required data not found"
    if (" " in username):
        return "Username contains illegal characters: whitespace"
    elif ("," in username):
        #Używany do udostepniania dla wielu użytkowników
        return "Username contains illegal characters: comma"
    if (len(username) > 100):
        return "Too long username"
    

    #Podstawowa weryfikacja poprawnosci e-mail
    email_re = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if not (re.match(email_re, email)):
        return "Invalid e-mail", 400
    if (len(email) > 100):
        return "Too long e-mail"

    #Potwierdzenie hasla, poniewaz staram sie zachecic uzytkownika do wzmocnienia hasla, a im dluzsze tym latwiej o pomylke
    if password != confirmation:
        return "Passwords do not match!", 400

    #Liczenie entropii w innym pliku
    ent, pass_msg = tools.passwordEntropy(password)

    if (ent < 50):
        return "Password is too weak! Use more characters and make sure to use both small and capital letters, digits and special characters! <br> Account not created."

    #Tworzenie hasha w innym pliku
    hash = tools.hash_password(password)
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    db_user = sql.execute("SELECT * FROM users WHERE username=:username", {"username":username}).fetchone()
    db_email = sql.execute("SELECT * FROM users WHERE email=:email", {"email":email}).fetchone()
    if(db_user == None and db_email == None):
        #Szybkie sprawdzenie, czy uzytkownik probowal wpisac jakies podejrzane rzeczy w pola tekstowe
        #Za to, ze nie zadzialaja odpowiadaja inne elementy kodu, tutaj tylko logowanie, aby latwiej bylo zidentyfikowac kto, co i kiedy
        if("<script>" in email or "<script>" in username):
            logger.log(request, "SUSPICIOUS", "Registration form possible script injection %s %s" % (email, username))
        if("'" in email or "'" in username):
            logger.log(request, "SUSPICIOUS", "Registration form possible SQL injection %s %s" % (email, username))
        
        #Rejestracja
        sql.execute("INSERT INTO users (email, username, password) VALUES (:email, :username, :password)", {"email":email, "username":username, "password": hash})
        db.commit()
        logger.log(request, "REGISTER", "Registered user %s %s" % (email, username))
        content = "Your registration was successful!" 
        logger.log(request, "EMAIL_SENT", ("Addr:%s;Content:%s" % (email, content)))
        return "Registration successful - confirmation e-mail sent!<br>" + pass_msg

    elif(db_user == None and db_email != None):
        #Email juz zarejestrowany -> pominac rejestracje oraz przypomniec uzytkownikowi ze juz ma konto przez email.
        #Gdy uzytkownik zobaczy ze po rejestracji dalej logowanie nie dziala powinien sprawdzic e-mail zgodnie z informacja o wyslanym potwierdzeniu
        logger.log(request, "REGISTER_FAIL", "Already registered email %s" % email)
        content = "You already have account registered or this email!<br> <a href=" + "http://127.0.0.1:5000/resetPassword" + ">Reset password </a>" 
        print("Sending email... %s %s" % (email, content))
        logger.log(request, "EMAIL_SENT", ("Addr:%s;Content:%s" % (email, content)))
        return "Registration successful - confirmation e-mail sent!<br>" + pass_msg

    #Nazwa uzytkownika zajeta -> mozna o tym poinformowac dzieki mechanizmowi potwierdzen email
    logger.log(request, "REGISTER_FAIL", "Already registered username %s" % username)
    return "Username already in use", 400

@app.route("/login")
def login():
    return render_template("login.html")
@app.route("/login", methods = ['POST'])
def loginUser():
    email = request.form.get("email")
    password = request.form.get("password")
    for arg in [email, password]:
        if (len(arg) < 1):
            return "Required data not found"
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()

    #Sprawdza, czy użytkownik jest tymczasowo zablokowany 1=ban 0=dostęp
    res = login_ban_handler.verifyUserBan(db, email, MAX_LOGIN_ATTEMPTS, ACCOUNT_SUSPENSION_TIME)
    if (res == 1):
        logger.log(request, "LOGIN_FAIL", ("Login failed on %s account because of ban" % email))
        return "Account temporarily blocked"

    db_hash = sql.execute("SELECT password FROM users WHERE email = :email", {"email":email}).fetchone()
    if (db_hash != None):
        db_hash = db_hash[0]
        hash = tools.hash_password_salt(password, db_hash)
        if (hash == db_hash):
            #Logowanie użytkownika - można usunąć wszystkie nieudane próby z bazy
            login_ban_handler.deleteAllAttempts(db, email)
            username = sql.execute("SELECT username from users WHERE email=:email", {"email":email}).fetchone()[0]
            user = user_loader(username)
            login_user(user)
            logger.log(request, "LOGIN", ("User %s logged in" % user.id))
            return redirect('/mynotes')

    #Zapis nieudanej próby - zwraca aktualną ilość złych logowań (włącznie z tym właśnie dodanym)
    count = login_ban_handler.saveFailedLogin(db, email, request)
    logger.log(request, "LOGIN_FAIL", ("Login failed on %s account" % email))

    if (count >= MAX_LOGIN_ATTEMPTS-2 and count < MAX_LOGIN_ATTEMPTS):
        #Pozostało 2 lub mniej prób -> informacja dla użytkownika
        return "Incorrect email or password <br> %i attempts remaining" % (MAX_LOGIN_ATTEMPTS-count), 401
    
    if (count >= MAX_LOGIN_ATTEMPTS):
        #Czas zablokować użytkownika. Na e-mail otrzyma link do odblokowania konta i zmiany hasła
        logger.log(request, "USER_BAN", ("%s banned for too many login fails" % email))
        token = jwtbuilder.buildUnbanJWT((email))
        content = "<a href=" + "http://127.0.0.1:5000/unban?token=" + token + "> Click to unban </a>"
        content = content + "<br> <a href=" + "http://127.0.0.1:5000/resetPassword" + ">Reset your password</a>" 
        logger.log(request, "EMAIL_SENT", ("Addr:%s;Content:%s" % (email, content)))
        return ("Sending email... %s %s" % (email, content))

    #W pozostałych przypadkach logowanie odrzucone bez zbyt szczegółowych informacji co było nie tak
    return "Incorrect email or password", 401

@app.route("/create")
@login_required
def createNote():
    return render_template("createNote.html")


@app.route("/create", methods = ['POST'])
@login_required
def saveNewNote():
    #Pobranie danych i walidacja
    username = current_user.id

    title = request.form.get("title")
    if(title == ""):
        title = "Untitled"
    if(len(title) > 100):
        return "Title too long"
    picture_url = request.form.get('picture')

    ext_string = "|".join(FILE_ALLOWED_EXTENSIONS)
    #Sprawdzenie url wyrazeniem regularnym
    url_re = r'\b(http:\/\/|https:\/\/)[A-Za-z0-9!"#$%&\'()*+.,\-\/:;<=>?@[\\\]^_`{|}~*$]+\.('+ ext_string +r')\b'
    if (picture_url != ""):
        if not (re.match(url_re, picture_url)):
            return "Invalid picture url<br>Only http and https link accepted<br>Accepted extensions: " + " ".join(FILE_ALLOWED_EXTENSIONS), 400
        if (".." in picture_url or "%2E%2E" in picture_url):
            logger.log(request, "SUSPICIOUS", "Possible path traversal attempt %s %s" % (username, picture_url))
            return "Invalid picture url<br>Only http and https link accepted<br>Accepted extensions: " + " ".join(FILE_ALLOWED_EXTENSIONS), 400
        if ("%00" in picture_url):
            logger.log(request, "SUSPICIOUS", "Possible null byte poisoning attempt %s %s" % (username, picture_url))
            return "Invalid picture url<br>Only http and https link accepted<br>Accepted extensions: " + " ".join(FILE_ALLOWED_EXTENSIONS), 400
    privacy = request.form.get("privacy")
    if(privacy not in ["private","unlisted","public"]):
        logger.log(request, "SUSPICIOUS", "Note privacy not in list %s" % privacy)
        return redirect("/create")
    allowed = ""
    #Jeśli prywatność ustawiona na unlisted to przeczytać notatkę lub spróbować ją odszyfrować hasłem mogą tylko użytkownicy z listy, którzy mają link
    #Wyjątek -> allowed="" wtedy każdy z linkiem może przeczytać/odszyfrować hasłem
    if(privacy == "unlisted"):
        allowed = request.form.get("allowedUsers")
    password = request.form.get("password")
    hash = "" #inicjalizacja, na wypadek jakby nie było hasła
    encrypt = request.form.get("encrypt")
    #Zamiana zmiennej encrypt z "on"/"off" na 1/0, gdzie 1 to włączona
    if(encrypt == "on"):
        encrypt = 1
        #Tworzę klucz do AES na podstawie hasła podanego przez użytkownika -> więcej w odpowiednim pliku
        user_key, hash = notecrypt.get_user_key(password)
    elif(encrypt == "off" or encrypt is None):
        encrypt = 0
    else:
        logger.log(request, "SUSPICIOUS", "Create note checkbox value error %s %s" % (encrypt, username))
        return redirect("/create")

    note = request.form.get("note")
    if(len(title) > 500):
        return "Note too long"
    
    #Sprawdzenie potencjalnych prób SQL injection
    if(True in ["'" in text for text in [title,note]]):
        logger.log(request, "SUSPICIOUS", "Create note form possible SQL injection %s %s" % (title, username))
    #Sprawdzenie potencjalnych prób code injection
    if(True in ["<script>" in text for text in [title,note]]):
        logger.log(request, "SUSPICIOUS", "Create note form possible code injection %s %s" % (title, username))

    #Najpierw zajmuje się notatką tekstową
    if(encrypt == 1):
        #Notatki szyfrowane są podwójnie: raz kluczem serwera, raz kluczem użytkownika
        note = notecrypt.encrypt_note_with_user_password(note, user_key)
        note = notecrypt.encrypt_note(note)
    elif(privacy == "private" or privacy == "unlisted"):
        #Jeśli notatka jest prywatna to jest również szyfrowana, ale tylko kluczem serwera
        note = notecrypt.encrypt_note(note)

    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    logger.log(request, "CREATE_NOTE", "New note created by %s" % username)
    sql.execute("INSERT INTO notes (username, title, privacy, note, encrypt, password, allowed) VALUES (:username, :title, :privacy, :note, :encrypt, :password, :allowed)",
     {"username":username, "title": title, "privacy": privacy, "note": note, "encrypt": encrypt, "password": hash, "allowed": allowed})
    db.commit()
    recent_id = sql.lastrowid

    #Zajmuje się zdjęciem

    #Usunięcie starych zdjęc z aktualnym id notatki (nigdy nie powinno takich być, ale dla pewności zabezpiecza)
    pics = glob.glob(NOTEPIC_SAVE_FOLDER + "/" + str(recent_id) + ".*")
    if (len(pics) > 0):
        for p in pics:
            os.remove(p)
        
    if (picture_url == ""):
        #Nie ma URL do zdjęcia, więc to wszystko
        return redirect("/render/" + str(recent_id))
    try:
        response = requests.get(picture_url, stream=True)
        logger.log(request, "REQUEST_SENT", "GET url %s" % picture_url)
        response_content = b''
        response_size = 0
        response_start = time.time()
        #Pobieranie w formie stream, aby przypadkiem nie pobrać pliku tak dużego, że nawet w formie tymczasowej mógłby być problemem
        for chunk in response.iter_content(1024):
            if (time.time() - response_start > 10): #10 sekund
                logger.log(request, "CREATE_NOTE", "Create note fail - donwload request timeout")
                return "Error during image download"
            response_size += len(chunk)
            if (response_size > FILE_MAX_SIZE):
                logger.log(request, "CREATE_NOTE", "Create note fail - donwload request response too large")
                return "Image too large<br>Max file size is " + FILE_MAX_SIZE
            response_content += chunk

        if (len(response_content) > FILE_MAX_SIZE):
            logger.log(request, "CREATE_NOTE", "Create note fail - donwload request response too large")
            return "Image too large<br>Max file size is " + FILE_MAX_SIZE

        #Zapisuje do tymczasowego pliku, sprawdza rzeczywistą strukturę pliku
        temp_filepath = TEMP_SAVE_FOLDER + "/" + str(recent_id) + ".png"
        open(temp_filepath, "wb").write(response_content)
        kind = filetype.guess(temp_filepath)
        os.remove(temp_filepath)
        if kind is None:
            #Nie udało się zgadnąć, rozszerzenie nieznane, nie można zapisać
            logger.log(request, "SUSPICIOUS", "Invalid file type during note creation")
            return "File invalid", 400
        if kind.extension in FILE_ALLOWED_EXTENSIONS:
            #Zapisuje w rzeczywistym folderze
            filename = "/"+ str(recent_id) + "." + str(kind.extension)
            filepath = os.path.join(NOTEPIC_SAVE_FOLDER + filename)
            data = ""
            if (encrypt == 1):
                data = notecrypt.encrypt_note_with_user_password(response_content, user_key)
                data = notecrypt.encrypt_note(data)
            elif (privacy == "private" or privacy == "unlisted"):
                data = notecrypt.encrypt_note(response_content)
            else:
                data = response_content
            logger.log(request, "CREATE_NOTE", "New file saved %s %s" % (username, filepath))
            open(filepath, "wb").write(data)
        else:
            return "Unallowed filetype", 400
    except Exception as e:
        print(e)
        logger.log(request, "CREATE_NOTE", "Creation fail - incorrect data %s %s" % (picture_url, username))
        return "Incorrect data", 400
    return redirect("/render/" + str(recent_id))

@app.route("/render/<id>", methods=['GET','POST'])
def renderNote(id, password=None):
    #2 metody: GET dla notatek nieszyfrowanych przez użytkownika, POST z hasłem dla notatek szyfrowanych
    if(request.method == 'POST'):
        password = request.form.get("password")
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    try:
        author, title, privacy, note, encrypt, db_hash, allowed = sql.execute("SELECT username, title, privacy, note, encrypt, password, allowed FROM notes WHERE id = :id", {"id":id}).fetchone()
    except:
        return redirect("/")

    if (privacy == "private"):
        if not (current_user.is_authenticated):
            return "Login to browse private notes!"
        username = current_user.id
        if (username != author):
            return "You are not the author!"
    elif (privacy == "unlisted"):
        if (allowed != ""):
            allowed_users = allowed.split(",")
            if not (current_user.is_authenticated):
                return "This note settings require login"
            username = current_user.id
            if not (username in allowed_users or username == author):
                logger.log(request, "SUSPICIOUS", "User %s tried to see unlisted note without permission" % username)
                return "You are not allowed to see this note"


    if(encrypt == 1):
        #Proste przekierowanie, jeśli nie ma hasła a powinno być
        if (password is None):
            return redirect("/enterNotePassword?note="+str(id))
        #Szybka weryfikacja hasha, lepsza kontrola nad działaniem w porównaniu do deszyfrowania na ślepo
        hash = tools.hash_password_salt(password, db_hash)
        if (hash != db_hash):
            return "Invalid data"
        
    if (encrypt == 0 and privacy != "public"):
        
        note = notecrypt.decrypt_note(note)
        note = note.decode()
    elif (encrypt == 1):
        user_key, hash = notecrypt.get_user_key(password, db_hash)
        note = notecrypt.decrypt_note(note)
        note = notecrypt.decrypt_note_user_password(note, user_key)
        note = note.decode()

    

    note = markdown.markdown(note)
    #Tekst wybielony przed wyswietleniem
    #Tytuły nie są stylowane, więc czyszczeniem zajmie się JINJA
    note = tools.cleanText(note)

    #Pobranie załączonego zdjęcia
    #Wyszukanie zdjęcia z folderu
    pics = glob.glob(NOTEPIC_SAVE_FOLDER + "/" + str(id) + ".*")
    if len(pics) > 0:
        default_pic = False
        path = pics[0]
    else:
        default_pic = True
        path = NOTEPIC_SAVE_FOLDER + "/default.png"

    #Wczytanie danych zdjęcia
    f = open(path, "rb")
    pic = f.read()
    f.close()
    if not default_pic:
        if (privacy != "public" or encrypt == 1):
            #Dekrypcja w zależności od potrzeb
            if (encrypt == 1):
                pic = notecrypt.decrypt_note(pic)
                pic = notecrypt.decrypt_note_user_password(pic, user_key)
            elif (privacy != "public"):
                pic = notecrypt.decrypt_note(pic)
    ext = path.split(".")[-1]
    mimetype = "image/" + ext
    myImage = base64.b64encode(pic).decode("utf-8")
    #Przestłanie szablonu razem ze zdjęciem kodowanym w base64
    return render_template("render.html", note=note, title=title, mimetype = mimetype, myImage = myImage)

@app.route("/enterNotePassword")
def enterNotePassword():
    #Mały, prosty formularz do wpisania hasła do notatki
    return render_template("enterNotePassword.html")




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
    for idx, note in enumerate(private_notes):
        note = list(note)
        if type(note[1]) is bytes:
            note[1] = notecrypt.decrypt_note(note[1]).decode()
            private_notes[idx] = note
    return render_template("browse.html",  public_notes=private_notes)


@app.route("/resetPassword")
def resetpassword():
    #Proste przekierowania
    args = request.args
    if(args.get("token") is not None):
        return render_template("newPassword.html")
    return render_template("resetPassword.html")
@app.route("/resetPassword", methods = ['POST'])
def sendResetEmail():
    email = request.form.get("email")
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    #Pobiera użytkownika z podanym emailem
    try:
        sql.execute("SELECT username, email FROM users WHERE email = :email", {"email":email})
        row = sql.fetchone()
        username, email= row
    except:
        #W aktualnym stanie na podstawie przekierowań można odczytać, czy dany email jest zarejestrowany
        #Oczywiście wynika to z uproszczenia aplikacji w celu ułatwienia testowania/sprawdzania
        #W realnych warunkach zamiast wysłania maila funkcja zwracałaby takie samo przekierowanie w każdym przypadku
        return redirect("/")
    logger.log(request, "PASSWORD_RESET", "User asked to reset his password %s %s" % (email, username))
    #Koduje dane do tokenu i wysyła na email
    token = jwtbuilder.buildUserDataJWT(row)
    return ("Sending email... %s %s" % (email, "http://127.0.0.1:5000/resetPassword?token="+token))

@app.route("/updatePassword", methods = ['POST'])
def saveNewPassword():
    password = request.form.get('password')
    token = request.form.get('token')
    data = jwtbuilder.decodeUserDataJWT(token)
    if (data == 1):
        #Funkcja decode zwraca 1 jeśli token jest nieaktualny
        return "Token invalid"
    username = data['payload'][0]
    email = data['payload'][1]
    hash = tools.hash_password(password)
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    logger.log(request, "PASSWORD_RESET", "User changed his password %s %s" % (email,username))
    sql.execute("UPDATE users SET password=:password WHERE username=:username AND email=:email", {"password":hash, "username":username, "email":email})
    db.commit()
    return "Success"

@app.route("/me")
@login_required
def myData():
    username = current_user.id
    return render_template("me.html", username=username)

#2 metody zwiazane z wgrywaniem pliku z dysku jako zdjecie profilowe uzytkownika
#napisane, poniewaz zle przeczytalem wymagania projektu, a szkoda usuwac
'''
@app.route("/updateAvatar", methods=['POST'])
@login_required
def updateAvatar():
    if 'file' not in request.files:
        return redirect("/me")
    file = request.files['file']
    if file.filename == "":
        return redirect("/me")
    if file.filename.split(".")[-1] not in FILE_ALLOWED_EXTENSIONS:
        return "Unallowed filetype"
    db = sqlite3.connect(DB_FILE)
    sql = db.cursor()
    try:
        id = sql.execute("SELECT id FROM users WHERE username=:username", {"username": current_user.id}).fetchone()[0]
        temp_filepath = os.path.join(TEMP_SAVE_FOLDER  + "/" + str(id)+".png")
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
'''
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


@app.route("/unban")
def unban():
    args = request.args
    if(args.get("token") is not None):
        token = args.get("token")
        data = jwtbuilder.decodeUnbanJWT(token)
        email = data['payload']
        if (email == 1):
            return "Token invalid"
        print(email)
        login_ban_handler.deleteAllAttempts(sqlite3.connect(DB_FILE), email)
        logger.log(request, "UNBAN", ("Account %s unbanned by email link" % email))
        return "Unban successful"
    return "Token invalid"
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
        sql.execute("INSERT INTO users (id, email, username, password) VALUES (1, 'bob@bob.com', 'bob', '$5$rounds=535000$YPsByhiXdwXli43D$pa5pvxcsyGpxMD3uhy32dBrYAw5xyjbaPsT/LS98UL0');")

        sql.execute("DROP TABLE IF EXISTS login_attempts;")
        sql.execute("CREATE TABLE login_attempts (ip varchar(12), email varchar(100), date datetime)")
        sql.execute("DELETE FROM login_attempts")

        sql.execute("DROP TABLE IF EXISTS notes;")
        sql.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, username varchar(100), title varchar(100), privacy varchar(10), note varchar(700), encrypt INTEGER, password varchar(128), allowed varchar(256));")
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


if __name__ == "__main__":
    app.run("0.0.0.0", 5000)