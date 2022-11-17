from flask import Flask, render_template, request, make_response

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
    email = request.form.get("email")
    password = request.form.get("password")
    confirmation = request.form.get("confirm-password")
    if password != confirmation:
        return "Passwords do not match!", 409
    return "Not implemented yet"

@app.route("/login")
def login():
    return render_template("login.html")
@app.route("/login", methods = ['POST'])
def loginUser():
    username = request.form.get("username")
    password = request.form.get("password")
    return "Not implemented yet"

@app.route("/browse")
def browse():
    return "Not implemented yet"