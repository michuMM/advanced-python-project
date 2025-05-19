import time
import base64
import matplotlib.pyplot as plt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ================= RSA TESTS ===================

import time
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def rsa_max_message_length(key_size_bits):
    return (key_size_bits // 8) - 2 * 20 - 2  # zakładamy SHA-1

def test_rsa_times():
    key_lengths = [1024, 2048, 3072]
    results = []

    for key_len in key_lengths:
        print(f"\n🔑 RSA {key_len}-bit key:")
        
        start = time.time()
        key = RSA.generate(key_len)
        end = time.time()
        gen_time = end - start
        print(f"  Czas generowania klucza: {gen_time:6f} s")

        public_key = key.publickey()
        cipher_rsa_enc = PKCS1_OAEP.new(public_key)
        cipher_rsa_dec = PKCS1_OAEP.new(key)

        max_len = rsa_max_message_length(key_len)
        msg_lengths = list(range(10, max_len + 1, int(max_len / 5)))

        for msg_len in msg_lengths:
            message = b"A" * msg_len
            enc_times = []
            dec_times = []

            for _ in range(20):
                start = time.time()
                ciphertext = cipher_rsa_enc.encrypt(message)
                enc_times.append(time.time() - start)

                start = time.time()
                decrypted = cipher_rsa_dec.decrypt(ciphertext)
                dec_times.append(time.time() - start)

            avg_enc = sum(enc_times) / len(enc_times)
            avg_dec = sum(dec_times) / len(dec_times)

            results.append({
                "alg": "RSA",
                "key_len": key_len,
                "msg_len": msg_len,
                "gen_time": gen_time,
                "enc_time": avg_enc,
                "dec_time": avg_dec
            })
            print(f"    {msg_len}B: enc {avg_enc:.6f}s, dec {avg_dec:.6f}s")

    return results

def test_aes_times():
    results = []
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    msg_lengths = [16, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]

    for msg_len in msg_lengths:
        message = pad(b"A" * msg_len, AES.block_size)
        enc_times = []
        dec_times = []

        for _ in range(20):
            cipher = AES.new(key, AES.MODE_CBC, iv)
            dec_cipher = AES.new(key, AES.MODE_CBC, iv)

            start = time.time()
            ciphertext = cipher.encrypt(message)
            enc_times.append(time.time() - start)

            start = time.time()
            plaintext = dec_cipher.decrypt(ciphertext)
            dec_times.append(time.time() - start)

        avg_enc = sum(enc_times) / len(enc_times)
        avg_dec = sum(dec_times) / len(dec_times)

        results.append({
            "alg": "AES",
            "msg_len": msg_len,
            "enc_time": avg_enc,
            "dec_time": avg_dec
        })
        print(f"    AES {msg_len}B: enc {avg_enc:.6f}s, dec {avg_dec:.6f}s")

    return results


# ================= WYKRESY ===================

def plot_results(rsa_results, aes_results):
    import matplotlib.pyplot as plt

    # ===== WYKRES DLA RSA =====
    plt.figure(figsize=(10, 6))
    for key_len in sorted(set(r["key_len"] for r in rsa_results)):
        subset = [r for r in rsa_results if r["key_len"] == key_len]
        x = [r["msg_len"] for r in subset]
        y_enc = [r["enc_time"] for r in subset]
        y_dec = [r["dec_time"] for r in subset]

        plt.plot(x, y_enc, label=f'RSA {key_len} enc', marker='o')
        plt.plot(x, y_dec, label=f'RSA {key_len} dec', marker='x')

    plt.xlabel("Długość wiadomości (B)")
    plt.ylabel("Czas (s)")
    plt.title("RSA: Czas szyfrowania / deszyfrowania vs długość wiadomości")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # ===== WYKRES DLA AES =====
    plt.figure(figsize=(10, 6))
    aes_x = [r["msg_len"] for r in aes_results]
    aes_enc = [r["enc_time"] for r in aes_results]
    aes_dec = [r["dec_time"] for r in aes_results]

    plt.plot(aes_x, aes_enc, label="AES enc", linestyle="--", marker="o")
    plt.plot(aes_x, aes_dec, label="AES dec", linestyle="--", marker="x")

    plt.xlabel("Długość wiadomości (B)")
    plt.ylabel("Czas (s)")
    plt.title("AES: Czas szyfrowania / deszyfrowania vs długość wiadomości")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

# ================= MAIN ===================

if __name__ == "__main__":
    print("⏱ Start testów RSA...")
    rsa_data = test_rsa_times()

    print("\n⏱ Start testów AES...")
    aes_data = test_aes_times()

    print("\n📊 Generuję wykresy...")
    plot_results(rsa_data, aes_data)
