import datetime
import json
import base64
import os

from cryptography.hazmat.primitives.asymmetric import padding as padding_asym
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding as padding_sym
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def datetime_to_string_conv(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()

class Communication():

    def send_out(self, to_be_sent, address, sock):
        print(to_be_sent)
        jay = json.dumps(to_be_sent)
        sock.sendto(jay.encode(encoding="utf-8"), address)

class Cripthography():

    def hybrid_cipher(self, subject, id, target, request, target_public_key, session_key):
        '''
        Employs hybrid encryption: Encrypts message with secret, and encrypts secret with target public key.
        Afterwards prepares and returns a message to be sent out, containing the prior.
        :param subject: Label of this message ('create' for auction creation, 'bid' for bid creation, etc)
        :param id: Serial ID number of the client's CC card, for identification purposes.
        :param target: Specify 'Manager' or 'Repository', to aquire the respective keys.
        :param request: JSON message to be serialized and sent out.
        :return: Message containing serialized and encrypted JSON request, and encrypted secret associated
        '''
        jay = json.dumps(request, default=datetime_to_string_conv).encode(encoding="utf-8")

        secret = os.urandom(32)
        iv = os.urandom(16)
        ciphertext = self.encrypt_symmetric(jay, secret, iv)

        cipher_secret = self.encrypt_symmetric(secret, session_key, iv)

        double_cipher_secret = self.encrypt_assymetric_public(
            cipher_secret,
            target_public_key,

        )

        return {
            "requestType": subject,
            "user_id": id,
            "cipher_text": base64.encodestring(ciphertext).decode(),
            "hybrid_secret": base64.encodestring(double_cipher_secret).decode(),
            "iv": base64.encodestring(iv).decode()
        }

    def serialize_public_key(self, public_key):
        """
        Serializes the user's public key
        :return: Serialized public key
        """
        return public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_symmetric(self, message, secret, iv):
        """
        Encrypt message with a symmetric algorithm, using a shared secret between client and \"destination\".
        :param message: The message
        :param destination: Destination of this message. Either \"Manager\" or \"Repository\". Will fetch secret betwen client and destination.
        :return: Encrypted data
        """
        padder = padding_sym.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        cipher = Cipher(algorithms.AES(secret), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()


    def decrypt_with_secret(self, key, ciphertext, iv):

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dencryptor = cipher.decryptor()
        padded_data = dencryptor.update(ciphertext) + dencryptor.finalize()

        unpadder = padding_sym.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()



    def encrypt_assymetric_public(self, bytes, public_key):
        """
        Encrypts a bytes object with a specified public key.
        :param bytes: Message to be encrypted.
        :param public_key: Specified public key to encrypt bytes.
        :return: Public key-encrypted bytes
        """


        return public_key.encrypt(
            bytes,
            padding_asym.OAEP(
                mgf=padding_asym.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


    def decrypt_assymetric_private(self, cipher, priv_key):
        """
        Decrypt asymmetrically encrypted message, with own private key.
        :param cipher: Ciphertext to be decrypted
        :return:
        """
        return priv_key.decrypt(
            cipher,
            padding_asym.OAEP(
                mgf=padding_asym.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )



    def parse_valid_message(self, msg, sender, key, priv_key):
        hybrid_secret = base64.b64decode(msg["hybrid_secret"])
        cipher_text = base64.b64decode(msg["cipher_text"])
        iv = base64.b64decode(msg["iv"])

        sessioned_secret = self.decrypt_assymetric_private(hybrid_secret, priv_key)
        true_secret = self.decrypt_with_secret(key, sessioned_secret, iv)


        true_message = self.decrypt_with_secret(true_secret, cipher_text, iv)

        try:
            return json.loads(true_message)
        except json.JSONDecodeError:
            print(str(true_message), " wasn't a JSON.")
            return true_message

class Utilities():
    def xor_2strs(self, s1,s2):
        return "".join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))
