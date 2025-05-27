
import time 
import random 
import string 
import json 
import base64 
import hashlib 
import hmac 
from collections import deque
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes 
from Crypto.Protocol.KDF import HKDF 
from Crypto.Hash import SHA256



DICTIONARY_ROTATION_INTERVAL = 60  

class DictionaryManager: 
    # Original constructor
    # def init(self, current_dict): 
    #     self.current_dict = current_dict

    def __init__(self, current_dict): 
        self.current_dict = current_dict

    def evolve(self, message, nonce, entropy):
        seed_input = json.dumps(self.current_dict, sort_keys=True) + message + nonce + entropy
        seed = hashlib.sha256(seed_input.encode()).hexdigest()
        chars = list(self.current_dict.keys())
        random.Random(seed).shuffle(chars)
        new_dict = dict(zip(chars, [format(i, f'0{256}b') for i in range(len(chars))]))
        self.current_dict = new_dict
        return new_dict



class Encoder: 
    @staticmethod 
    def encode(message, dict_):
        return ''.join([dict_.get(ch, '') for ch in message])

    @staticmethod
    def decode(binary, dict_):
        reverse_dict = {v: k for k, v in dict_.items()}
        size = len(next(iter(reverse_dict)))
        return ''.join([reverse_dict.get(binary[i:i+size], '?') for i in range(0, len(binary), size)])



def validate_pow(nonce, difficulty=5): 
    return hashlib.sha256(nonce.encode()).hexdigest().startswith('0' * difficulty)



class SecureStorage: 
    # Original methods
    # def derive_key(self, nonce): 
    #     salt = b"secure-messaging-salt" 
    #     return HKDF(nonce.encode(), 32, salt, SHA256)

    def derive_key(self, nonce): 
        salt = b"secure-messaging-salt" 
        return HKDF(nonce.encode(), 32, salt, SHA256)

    def encrypt(self, message, nonce):
        key = self.derive_key(nonce)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def decrypt(self, encoded, nonce):
        raw = base64.b64decode(encoded)
        nonce_bytes, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        key = self.derive_key(nonce)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce_bytes)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()



class QRHandshake: 
    # Original constructor
    # def init(self, user_id): 
    #     self.user_id = user_id 
    #     self.dict = self.generate_initial_dict() 
    #     self.decoder_logic = "basic"

    def __init__(self, user_id): 
        self.user_id = user_id 
        self.dict = self.generate_initial_dict() 
        self.decoder_logic = "basic"

    def generate_initial_dict(self):
        chars = string.ascii_letters + string.digits + string.punctuation + ' '
        shuffled = list(chars)
        random.shuffle(shuffled)
        return dict(zip(chars, [format(i, f'0{256}b') for i in range(len(shuffled))]))

    def export_qr(self):
        return {
            "user": self.user_id,
            "dict": self.dict,
            "decoder_logic": self.decoder_logic
        }



class Sender:
    def __init__(self, recipient_id, dict_):
        self.recipient_id = recipient_id 
        self.dict_mgr = DictionaryManager(dict_)

    def send_message(self, message):
        # Keep trying until a valid nonce is found
        while True:
            nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            if validate_pow(nonce, difficulty=5):
                break

        entropy = get_random_bytes(8).hex()
        binary = Encoder.encode(message, self.dict_mgr.current_dict)

        # Embed seed-like noise
        noise = entropy[:4] + "::" + entropy[4:]  # simple embedding format
        binary_with_noise = binary + Encoder.encode(noise, self.dict_mgr.current_dict)

        new_dict = self.dict_mgr.evolve(message, nonce, entropy)

        payload = {
            "encoded": binary_with_noise,
            "nonce": nonce,
            "entropy": entropy,
            "timestamp": time.time()
        }
        return payload, new_dict




class Receiver: 
    # Original constructor
    # def init(self, sender_id, dict_):
    #      self.sender_id = sender_id
    #      self.dict_mgr = DictionaryManager(dict_)
    #      self.storage = SecureStorage()

    def __init__(self, sender_id, dict_):
         self.sender_id = sender_id
         self.dict_mgr = DictionaryManager(dict_)
         self.storage = SecureStorage()

    def try_decode_with_entropy(self, binary, nonce, entropy):
        try:
            temp_dict = DictionaryManager(self.dict_mgr.current_dict.copy())
            temp_dict.evolve("", nonce, entropy)
            message = Encoder.decode(binary, temp_dict.current_dict)
            return message
        except Exception:
            return None

    def receive_message(self, payload):
        current_time = time.time()
        if abs(current_time - payload["timestamp"]) > DICTIONARY_ROTATION_INTERVAL + 1000:
            return "Replay Attack Detected", None

        binary = payload['encoded']
        nonce = payload['nonce']
        entropy = payload['entropy']

        # Assume last 24 bits are noise, strip and decode
        noise_len = 256 * 8
        message_bin = binary[:-noise_len] if len(binary) > noise_len else binary

        message = Encoder.decode(message_bin, self.dict_mgr.current_dict)

        # Optional fallback
        if '?' in message:
            message = self.try_decode_with_entropy(binary, nonce, entropy) or "Desync detected"

        secure_msg = self.storage.encrypt(message, nonce)
        self.dict_mgr.evolve(message, nonce, entropy)
        return secure_msg, message



if __name__ == "__main__":
    qr = QRHandshake("user123") 
    qr_data = qr.export_qr()

    sender = Sender("user456", qr_data['dict'])
    receiver = Receiver("user123", qr_data['dict'])

    # Original code
    # payload, updated_sender_dict = sender.send_message("Hello Secure World!")
    # if isinstance(payload, str):
    #     print(payload)
    # else:
    #     secured_msg, plaintext = receiver.receive_message(payload)
    #     print("Encrypted & Stored Message:", secured_msg)
    #     print("Decrypted Message:", plaintext)

    result = sender.send_message("Hello Secure World!")
    if isinstance(result, str):
        print(result)
    else:
        payload, updated_sender_dict = result
        secured_msg, plaintext = receiver.receive_message(payload)
        print("Encrypted & Stored Message:", secured_msg)
        print("Decrypted Message:", plaintext)
