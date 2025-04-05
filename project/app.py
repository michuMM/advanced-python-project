from flask import Flask, render_template, request, redirect, url_for, session
import os, json
from stegano_utils import hide_message, reveal_message
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "sekret123"

UPLOAD_FOLDER = "uploads"
GENERATED_FOLDER = "generated"
USER_DB = "data/users.json"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(GENERATED_FOLDER, exist_ok=True)
os.makedirs("data", exist_ok=True)

# Inicjalizacja pustej bazy jeśli nie istnieje
if not os.path.exists(USER_DB):
    with open(USER_DB, "w") as f:
        json.dump({}, f)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        image = request.files["image"]

        filename = secure_filename(image.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        image.save(path)

        generated_path = os.path.join(GENERATED_FOLDER, f"{username}.png")
        hide_message(path, generated_path, username)

        with open(USER_DB) as f:
            users = json.load(f)
        users[username] = f"{username}.png"
        with open(USER_DB, "w") as f:
            json.dump(users, f)

        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        image = request.files["image"]

        filename = secure_filename(image.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        image.save(path)

        hidden_msg = reveal_message(path)

        if hidden_msg == username:
            session["username"] = username
            return redirect(url_for("success"))
        else:
            return redirect(url_for("fail"))
    return render_template("login.html")

@app.route("/success")
def success():
    if "username" not in session:
        return redirect(url_for("index"))
    return render_template("success.html", username=session["username"])

@app.route("/fail")
def fail():
    return render_template("fail.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)