from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os, json
from stegano_utils import hide_message, reveal_message, encode_lsb, decode_lsb
from werkzeug.utils import secure_filename
from encryption_utils import encrypt_aes, encrypt_rsa, encrypt_des, encrypt_ecc
from encryption_utils import decrypt_aes, decrypt_rsa, decrypt_des, decrypt_ecc
import time
from datetime import datetime

app = Flask(__name__)
app.secret_key = "sekret123"

UPLOAD_FOLDER = "uploads"
GENERATED_FOLDER = "generated"
USER_DB = "data/users.json"
STATS_DB = "data/stats.json"

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

@app.route("/stats")
def stats():
    return render_template("stats.html")

@app.route("/stats/data")
def stats_data():
    with open(STATS_DB) as f:
        data = json.load(f)
    return jsonify(data)

@app.route("/charts")
def charts():
    return render_template("charts.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        start_total = time.time()
        algorithm = request.form.get('algorithm')
        media_type = request.form.get('media_type')
        username = request.form["username"]
        uploaded_file = request.files["media"]

        filename = secure_filename(uploaded_file.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        uploaded_file.save(path)

        output_ext = "png" if media_type == "image" else "wav"
        generated_path = os.path.join(GENERATED_FOLDER, f"{username}.{output_ext}")

        # Długość wiadomości
        message_length = len(username)

        # --- Szyfrowanie ---
        start_encrypt = time.time()
        if algorithm == "aes":
            encrypted_username = encrypt_aes(username)
            key_length = 256
        elif algorithm == "rsa":
            encrypted_username = encrypt_rsa(username)
            key_length = 2048
        elif algorithm == "des":
            encrypted_username = encrypt_des(username)
            key_length = 56
        elif algorithm == "ecc":
            encrypted_username = encrypt_ecc(username)
            key_length = 256
        else:
            return "Nieznany algorytm", 400
        encryption_time = time.time() - start_encrypt

        # --- Kodowanie LSB ---
        start_encoding = time.time()
        if media_type == "image":
            hide_message(path, generated_path, encrypted_username)
        elif media_type == "audio":
            encode_lsb(path, encrypted_username, generated_path)
        else:
            return "Nieznany typ pliku", 400
        encoding_time = time.time() - start_encoding

        # Rozmiar pliku + bajty ukrytej wiadomości
        file_size = os.path.getsize(generated_path)
        hidden_data_bytes = len(encrypted_username.encode())

        # Zapis do users.json
        with open(USER_DB) as f:
            users = json.load(f)
        users[username] = {
            "file": f"{username}.{output_ext}",
            "alg": algorithm,
            "type": media_type
        }
        with open(USER_DB, "w") as f:
            json.dump(users, f, indent=4)

        # Zapis do stats.json
        entry = {
            "id": int(time.time()),  # unikalny timestamp jako id
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "username": username,
            "action": "register",
            "status": "success",
            "algorithm": algorithm.upper(),
            "keyLength": key_length,
            "messageLength": message_length,
            "fileFormat": media_type,
            "encryptionTime": round(encryption_time, 6),
            "decryptionTime": None,
            "encodingTime": round(encoding_time, 6),
            "decodingTime": 0.0,
            "fileSizeBytes": file_size,
            "hiddenDataSizeBytes": hidden_data_bytes,
            "totalTime": round(time.time() - start_total, 6)
        }

        # Dodaj wpis do pliku stats.json
        if os.path.exists(STATS_DB):
            with open(STATS_DB, "r") as f:
                stats = json.load(f)
        else:
            stats = []

        stats.append(entry)

        with open(STATS_DB, "w") as f:
            json.dump(stats, f, indent=4)

        return redirect(url_for("index", reg_time=f"{entry['totalTime']}"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        start_time = time.time()
        username = request.form["username"]
        uploaded_file = request.files["media"]

        filename = secure_filename(uploaded_file.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        uploaded_file.save(path)

        # Domyślne dane do statystyk
        format_file = "audio" if filename.lower().endswith(".wav") else "image"        

        # Wczytaj użytkowników
        with open(USER_DB) as f:
            users = json.load(f)

        user_data = users.get(username)
        if not user_data:
            action_result = "fail"
            success = False
            alg = "-"
            decrypted_msg = ""
            key_len = None
            decode_time = None
            decrypt_time = None
            hidden_msg = ""
        else:
            alg = user_data.get("alg", "aes")
            try:                
                if format_file == "audio":
                    decode_start = time.time()
                    hidden_msg = decode_lsb(path)
                    decode_end = time.time()
                    decode_time = decode_end - decode_start
                else:
                    decode_start = time.time()
                    hidden_msg = reveal_message(path)
                    decode_end = time.time()
                    decode_time = decode_end - decode_start

                decrypt_start = time.time()
                if alg == "rsa":
                    decrypted_msg = decrypt_rsa(hidden_msg)
                    key_len = 2048
                elif alg == "des":
                    decrypted_msg = decrypt_des(hidden_msg)
                    key_len = 56
                elif alg == "ecc":
                    decrypted_msg = decrypt_ecc(hidden_msg)
                    key_len = 256  # Przykładowo
                else:
                    decrypted_msg = decrypt_aes(hidden_msg)
                    key_len = 256

                decrypt_end = time.time()
                decrypt_time = decrypt_end - decrypt_start
                success = decrypted_msg == username
                action_result = "udane" if success else "nieudane"
            except Exception as e:
                print("Błąd podczas logowania:", e)
                decrypted_msg = ""
                decode_time = "-"
                decrypt_time = "-"
                key_len = "-"
                action_result = "nieudane"
                success = False

        # Wczytaj stats.json
        try:
            with open(STATS_DB, "r") as f:
                stats = json.load(f)
                if not isinstance(stats, list):
                    stats = []
        except (FileNotFoundError, json.JSONDecodeError):
            stats = []

        entry = {
            "id": int(time.time()),  # np. timestamp jako unikalny ID
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "username": username,
            "action": "login",
            "status": "success" if success else "fail",
            "algorithm": alg.upper() if isinstance(alg, str) else None,
            "keyLength": key_len if isinstance(key_len, int) else None,
            "messageLength": len(username),
            "fileFormat": format_file,
            "encryptionTime": None,
            "decryptionTime": round(decrypt_time, 6) if isinstance(decrypt_time, float) else None,
            "encodingTime": None,
            "decodingTime": round(decode_time, 6) if isinstance(decode_time, float) else None,
            "fileSizeBytes": os.path.getsize(path) if os.path.exists(path) else None,
            "hiddenDataSizeBytes": len(hidden_msg.encode()) if isinstance(hidden_msg, str) else None,
            "totalTime": round(time.time() - start_time, 6)
        }

        stats.append(entry)

        with open(STATS_DB, "w") as f:
            json.dump(stats, f, indent=4)

        # Przekierowanie po sukcesie/porazce
        if success:
            session["username"] = username
            print("Zalogowano jako:", username)
            duration = time.time() - start_time
            return redirect(url_for("success", reg_time=f"{duration:.4f}"))
        else:
            print("Nieprawidłowe logowanie:", username)
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