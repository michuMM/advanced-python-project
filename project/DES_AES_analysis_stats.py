from Crypto.Cipher import AES, DES
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import time
import matplotlib.pyplot as plt

NUM_RUNS = 50

def aes_test(message):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = message + b' ' * (16 - len(message) % 16)

    enc_times = []
    dec_times = []

    for _ in range(NUM_RUNS):
        start = time.perf_counter()
        ciphertext = cipher.encrypt(padded)
        enc_times.append(time.perf_counter() - start)

        decipher = AES.new(key, AES.MODE_CBC, iv)
        start = time.perf_counter()
        _ = decipher.decrypt(ciphertext)
        dec_times.append(time.perf_counter() - start)

    return sum(enc_times) / NUM_RUNS, sum(dec_times) / NUM_RUNS

def des_test(message):
    key = get_random_bytes(8)
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = message + b' ' * (8 - len(message) % 8)

    enc_times = []
    dec_times = []

    for _ in range(NUM_RUNS):
        start = time.perf_counter()
        ciphertext = cipher.encrypt(padded)
        enc_times.append(time.perf_counter() - start)

        decipher = DES.new(key, DES.MODE_CBC, iv)
        start = time.perf_counter()
        _ = decipher.decrypt(ciphertext)
        dec_times.append(time.perf_counter() - start)

    return sum(enc_times) / NUM_RUNS, sum(dec_times) / NUM_RUNS

def ecc_test(message):
    sign_times = []
    verify_times = []

    for _ in range(NUM_RUNS):
        key = ECC.generate(curve='P-256')
        signer = DSS.new(key, 'fips-186-3')
        verifier = DSS.new(key.public_key(), 'fips-186-3')
        h = SHA256.new(message)

        start = time.perf_counter()
        signature = signer.sign(h)
        sign_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        verifier.verify(h, signature)
        verify_times.append(time.perf_counter() - start)

    return sum(sign_times) / NUM_RUNS, sum(verify_times) / NUM_RUNS

def run_all_tests():
    print("Start testów AES / DES / ECC...")

    sizes = [16, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
    results = []

    for size in sizes:
        message = get_random_bytes(size)

        aes_enc, aes_dec = aes_test(message)
        des_enc, des_dec = des_test(message)
        #ecc_sign, ecc_verify = ecc_test(message)

        print(f"{size}B:")
        print(f"    AES: enc {aes_enc:.6f}s, dec {aes_dec:.6f}s")
        print(f"    DES: enc {des_enc:.6f}s, dec {des_dec:.6f}s")
        #print(f"    ECC: sign {ecc_sign:.6f}s, verify {ecc_verify:.6f}s")

        results.append({
            "size": size,
            "aes_enc": aes_enc,
            "aes_dec": aes_dec,
            "des_enc": des_enc,
            "des_dec": des_dec,
            #"ecc_sign": ecc_sign,
            #"ecc_verify": ecc_verify,
        })

    return results

def plot_results(results):
    sizes = [r["size"] for r in results]

    # AES & DES ENCRYPTION
    plt.figure(figsize=(10, 6))
    plt.plot(sizes, [r["aes_enc"] for r in results], label="AES enc", marker="o")
    plt.plot(sizes, [r["des_enc"] for r in results], label="DES enc", marker="x")
    plt.title("Czas szyfrowania AES vs DES")
    plt.xlabel("Rozmiar wiadomości (B)")
    plt.ylabel("Czas (s)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # AES & DES DECRYPTION
    plt.figure(figsize=(10, 6))
    plt.plot(sizes, [r["aes_dec"] for r in results], label="AES dec", marker="o")
    plt.plot(sizes, [r["des_dec"] for r in results], label="DES dec", marker="x")
    plt.title("Czas deszyfrowania AES vs DES")
    plt.xlabel("Rozmiar wiadomości (B)")
    plt.ylabel("Czas (s)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # ECC SIGN / VERIFY
    # plt.figure(figsize=(10, 6))
    # plt.plot(sizes, [r["ecc_sign"] for r in results], label="ECC sign", marker="o")
    # plt.plot(sizes, [r["ecc_verify"] for r in results], label="ECC verify", marker="x")
    # plt.title("Czas podpisywania i weryfikacji ECC")
    # plt.xlabel("Rozmiar wiadomości (B)")
    # plt.ylabel("Czas (s)")
    # plt.legend()
    # plt.grid(True)
    # plt.tight_layout()
    # plt.show()

# ================= MAIN ===================

if __name__ == "__main__":
    results = run_all_tests()
    print("\n📊 Generuję wykresy...")
    plot_results(results)
