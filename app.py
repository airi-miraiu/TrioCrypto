from flask import Flask, render_template, request
from Crypto.Cipher import AES, DES3, Blowfish, PKCS1_OAEP, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import base64, os

app = Flask(__name__)

def generate_key(algo):
    if algo == "AES":
        return os.urandom(16)  # 16-byte key for AES
    elif algo == "3DES":
        return DES3.adjust_key_parity(os.urandom(24))  # 24-byte key for 3DES
    elif algo == "Blowfish":
        return os.urandom(16)  # 16-byte key for Blowfish
    elif algo == "RSA":
        key = RSA.generate(2048)
        return key.export_key(), key.publickey().export_key()
    elif algo == "ChaCha20":
        return os.urandom(32)  # 32-byte key for ChaCha20
    elif algo == "XOR":
        return os.urandom(16)  # 16-byte key for XOR Cipher
    return None

def xor_encrypt_decrypt(data, key):
    key_length = len(key)
    return bytes([data[i] ^ key[i % key_length] for i in range(len(data))])

def encrypt_message(message, key, algo):
    message_bytes = message.encode()
    if algo == "AES":
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message_bytes, AES.block_size))
        return base64.b64encode(iv + encrypted).decode(), base64.b64encode(key).decode()
    elif algo == "3DES":
        iv = os.urandom(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message_bytes, DES3.block_size))
        return base64.b64encode(iv + encrypted).decode(), base64.b64encode(key).decode()
    elif algo == "Blowfish":
        iv = os.urandom(8)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message_bytes, Blowfish.block_size))
        return base64.b64encode(iv + encrypted).decode(), base64.b64encode(key).decode()
    elif algo == "RSA":
        public_key = RSA.import_key(key)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(message_bytes)
        return base64.b64encode(encrypted).decode(), None
    elif algo == "ChaCha20":
        nonce = os.urandom(8)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        encrypted = cipher.encrypt(message_bytes)
        return base64.b64encode(nonce + encrypted).decode(), base64.b64encode(key).decode()
    elif algo == "XOR":
        encrypted = xor_encrypt_decrypt(message_bytes, key)
        return base64.b64encode(encrypted).decode(), base64.b64encode(key).decode()
    return None, None

def decrypt_message(encrypted_message, key, algo):
    encrypted_bytes = base64.b64decode(encrypted_message)
    if algo == "AES":
        iv = encrypted_bytes[:16]
        encrypted_data = encrypted_bytes[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()
    elif algo == "3DES":
        iv = encrypted_bytes[:8]
        encrypted_data = encrypted_bytes[8:]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), DES3.block_size).decode()
    elif algo == "Blowfish":
        iv = encrypted_bytes[:8]
        encrypted_data = encrypted_bytes[8:]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), Blowfish.block_size).decode()
    elif algo == "RSA":
        private_key = RSA.import_key(key)
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(encrypted_bytes).decode()
    elif algo == "ChaCha20":
        nonce = encrypted_bytes[:8]
        encrypted_data = encrypted_bytes[8:]
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(encrypted_data).decode()
    elif algo == "XOR":
        decrypted = xor_encrypt_decrypt(encrypted_bytes, key)
        return decrypted.decode()
    return None

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    if request.method == "POST":
        algo = request.form.get("algorithm")
        operation = request.form.get("operation")
        plaintext = request.form.get("message")
        ciphertext = request.form.get("ciphertext")
        key_input = request.form.get("key")
        
        try:
            if operation == "Encrypt":
                if algo == "RSA":
                    private_key, public_key = generate_key(algo)
                    encrypted_message, _ = encrypt_message(plaintext, public_key, algo)
                    result = {
                        "ciphertext": encrypted_message,
                        "private_key": base64.b64encode(private_key).decode(),
                        "public_key": base64.b64encode(public_key).decode(),
                        "algorithm": algo
                    }
                else:
                    key = generate_key(algo)
                    encrypted_message, key_b64 = encrypt_message(plaintext, key, algo)
                    result = {
                        "ciphertext": encrypted_message,
                        "key": key_b64,
                        "algorithm": algo
                    }
            elif operation == "Decrypt":
                if not key_input or not ciphertext:
                    raise ValueError("Both ciphertext and key are required for decryption!")
                key = base64.b64decode(key_input)
                decrypted_message = decrypt_message(ciphertext, key, algo)
                result = {"plaintext": decrypted_message, "algorithm": algo}
        except Exception as e:
            result = {"error": str(e), "algorithm": algo}
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
