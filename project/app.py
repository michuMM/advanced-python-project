from flask import Flask, render_template, request, redirect, url_for, session
import os, json
from stegano_utils import hide_message, reveal_message
from werkzeug.utils import secure_filename
from encryption_utils import encrypt_aes, encrypt_rsa, encrypt_des, encrypt_ecc
from encryption_utils import decrypt_aes, decrypt_rsa, decrypt_des, decrypt_ecc
import time

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
    reg_time = request.args.get("reg_time")
    return render_template("index.html", reg_time=reg_time)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        start_time = time.time()
        algorithm = request.form.get('algorithm')
        print(f"Wybrany algorytm: {algorithm}")

        username = request.form["username"]
        image = request.files["image"]

        filename = secure_filename(image.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        image.save(path)

        generated_path = os.path.join(GENERATED_FOLDER, f"{username}.png")
        
        if algorithm == "aes":
            encrypted_username = encrypt_aes(username)
        elif algorithm == "rsa":
            encrypted_username = encrypt_rsa(username)
        elif algorithm == "des":
            encrypted_username = encrypt_des(username)
        elif algorithm == "ecc":
            encrypted_username = encrypt_ecc(username)
        else:
            return "Nieznany algorytm", 400

        hide_message(path, generated_path, encrypted_username)                    

        with open(USER_DB) as f:
            users = json.load(f)
        users[username] = {
            "img": f"{username}.png",
            "alg": algorithm
        }
        with open(USER_DB, "w") as f:
            json.dump(users, f)

        end_time = time.time()
        duration = end_time - start_time

        return redirect(url_for("index", reg_time=f"{duration:.4f}"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():    
    if request.method == "POST":
        start_time = time.time()
        username = request.form["username"]
        image = request.files["image"]

        filename = secure_filename(image.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        image.save(path)

        hidden_msg = reveal_message(path)
        print("Zaszyfrowana wiadomosc ukryta w obrazku: ", hidden_msg)

        with open(USER_DB) as f:
            users = json.load(f)

        user_data = users.get(username)
        if not user_data:
            return redirect(url_for("fail"))

        alg = user_data.get("alg", "aes")  # domyślnie AES, jakby coś było nie tak

        try:
            if alg == "rsa":
                decrypted_msg = decrypt_rsa(hidden_msg)
                print("Odszyfrowana wiadomosc ukryta w obrazku: ", decrypted_msg)
            elif alg == "des":
                decrypted_msg = decrypt_des(hidden_msg)
                print("Odszyfrowana wiadomosc ukryta w obrazku: ", decrypted_msg)
            elif alg == "ecc":
                decrypted_msg = decrypt_ecc(hidden_msg)
                print("Odszyfrowana wiadomosc ukryta w obrazku: ", decrypted_msg)
            else:
                decrypted_msg = decrypt_aes(hidden_msg)
                print("Odszyfrowana wiadomosc ukryta w obrazku: ", decrypted_msg)
        except:
            print("Błąd wewnętrzny serwera")
            return redirect(url_for("fail"))

        if decrypted_msg == username:
            session["username"] = username
            print("Zalogowano jako: ", username)
            end_time = time.time()
            duration = end_time - start_time
            return redirect(url_for("success", reg_time=f"{duration:.4f}"))
        else:
            print("Nieprawidłowe logowanie: ", username)
            return redirect(url_for("fail"))

        
        try:
            decrypted_msg = decrypt_aes(hidden_msg)            
        except:
            return redirect(url_for("fail"))

        if decrypted_msg == username:
            session["username"] = username
            end_time = time.time()
            duration = end_time - start_time
            return redirect(url_for("success", reg_time=f"{duration:.4f}"))
        else:
            return redirect(url_for("fail"))
    return render_template("login.html")

@app.route("/success")
def success():
    reg_time = request.args.get("reg_time")
    if "username" not in session:
        return redirect(url_for("index"))
    return render_template("success.html", username=session["username"], reg_time = request.args.get("reg_time"))

@app.route("/fail")
def fail():
    return render_template("fail.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)