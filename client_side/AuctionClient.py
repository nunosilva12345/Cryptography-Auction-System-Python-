import base64
import secrets

import PyKCS11
from _socket import socket, AF_INET, SOCK_DGRAM

from cryptography import x509, exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import json, datetime, os

from message_module.Cryptopuzzle import crypto_challenge, cryptopuzzle
from message_module.ExchangeMessages import Communication as comm
from message_module.ExchangeMessages import Cripthography as cipher_operations
from message_module.ExchangeMessages import Utilities as utils
from message_module.Utils import generate_asym_pair


def datetime_to_string_conv(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()

def create_if_not_exists(directory, folder):
    if not os.path.exists(directory + folder):
        os.makedirs(directory + folder)
        return True
    return False

class AuctionClient():
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.sessions = {}
        self.iv = os.urandom(16)
        self.pems = {}
        self.my_auction_pems = {}

        with open("client_side/pems/managerPublicPEM.pem", "rb") as key_file:
            self.pems["Manager"] = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            print("Manager public key loaded!")

        with open("client_side/pems/repositoryPublicPEM.pem", "rb") as key_file:
            self.pems["Repository"] = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            print("Repository public key loaded!")

    def sign_with_cc(self, session, challenge):
        print("PIN will be needed...")
        private_key = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
        ])[0]

        return session.sign(private_key, challenge, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None))


    def generate_keys(self, path, folder):
        """
        Creation of an asymmetric key-pair for this user, stored in a folder.
        Should it already exist, you just load it.
        :param path: pre-path to the folder
        :param folder: folder name - CC user ID
        :return: Nothing really.
        """
        private_key = None
        public_key = None

        if create_if_not_exists("client_side/users/", folder):
            klength = 4096

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=klength,
                backend=default_backend()
            )

            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                # encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
                encryption_algorithm=serialization.NoEncryption()
            )

            public_key = private_key.public_key()

            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                # encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
            )

            with open(path + folder + "/private.pem", "wb") as f:
                for l in pem_private.splitlines():
                    f.write(l + b"\n")

            with open(path + folder + "/public.pem", "wb") as f:
                for l in pem_public.splitlines():
                    f.write(l + b"\n")
        else:
            #TODO PASSWORD
            print("Folder {} already created.".format(folder))
            with open(path + folder + "/private.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            with open(path + folder + "/public.pem", "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )

        self.public_key = public_key
        self.private_key = private_key


    def setup_man_repo_conn(self, session):
        auc_client.setup_connection(session, "Manager", MANAGER_ADDRESS)
        auc_client.setup_connection(session, "Repository", REPOSITORY_ADDRESS)


    #TODO True/false return value
    def setup_connection(self, session, address_name, ADDRESS):
        """
        Prepares and executes a series of sends/receives to ensure both the client and the target server have established
        a safe channel and user is authenticated with the server.
        :param session: Current citizen card session, containing access to keys.
        :param address_name: Name of the target server
        :param ADDRESS: (IP,PORT) address tuple of the target server
        :return: Nothing. (I should have it return something...)
        """

        print("Setting up connection...")
        sock = socket(AF_INET, SOCK_DGRAM)

        all_attr = list(PyKCS11.CKA.keys())
        # Filter attributes
        all_attr = [e for e in all_attr if isinstance(e, int)]

        #Request a challenge
        tobesent = {
            "requestType" : "challenge_please"
        }
        comm().send_out(tobesent, ADDRESS, sock)

        #Golly gee I sure hope the server gave me a challenge
        data, server = sock.recvfrom(4096)
        received = json.loads(data)
        print("Response received.")
        if received["responseType"] == "challenge":
            #Grab the challenge and sign it with CC
            challenge = base64.decodestring(received["challenge"].encode())

            signature = self.sign_with_cc(session, challenge)

            #Aquire public key certificate to send with the signature
            CC_cert = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
                (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')
            ])[0]


            attr = session.getAttributeValue(CC_cert, all_attr)
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr),attr))
            print("Citizen's Card Public Key Certificate extracted.")
            bytesCert = bytes(attr['CKA_VALUE'])


            challenge = secrets.token_bytes(32)

            #Send out signature and public key certificate, and also a challenge for the server
            tobesent = {
                "requestType" : "challenge_response",
                "signature" : base64.encodestring(bytes(signature)).decode(),
                "certificate" : base64.encodestring(bytesCert).decode(),
                "challenge2" : base64.encodestring(challenge).decode()
            }
            print("Sending out certification and own challenge.")
            comm().send_out(tobesent, ADDRESS, sock)

            #Get the signature and verify it with the public key you aquired prior to this program
            data, server = sock.recvfrom(4096)
            received = json.loads(data)
            signature = base64.decodestring(received["signature"].encode())


            try:
                auc_client.pems[address_name].verify(
                    signature,
                    challenge,
                    padding.PSS(
                        mgf = padding.MGF1(hashes.SHA256()),
                        salt_length = padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Validation/Authentication complete!")
            except (exceptions.InvalidSignature):
                print("Server failed to answer challenge. Aborting!")
                exit(0)


            encoded = base64.encodestring(cipher_operations().serialize_public_key(self.public_key))

            tobesent = {
                "requestType": "pkeysend",
                "id": serial_number,
                "key": encoded.decode('ascii')
            }
            comm().send_out(tobesent, ADDRESS, sock)

            data, server = sock.recvfrom(4096)

            response = json.loads(data)

            print("Response received:\t{}".format(str(response)))
            if response["responseType"] == "ACK":
                print("All is right with the world.")

                decoded_secret = base64.b64decode(response["secret"])

                secret = cipher_operations().decrypt_assymetric_private(decoded_secret, auc_client.private_key)

                print("Secret aquired!")

                auc_client.sessions[address_name] = secret


            else:
                print("Something bad happened oh well.")
                exit(0)

    def validate_receipt(self):
        # TODO Comparar hash de bid minha a bid hash de uma auc terminada
        pass


auc_client = AuctionClient()
MANAGER_ADDRESS = ('127.0.0.1', 5252)
REPOSITORY_ADDRESS = ('127.0.0.1', 1234)

lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()

def store_receipt(receipt, sid):
    data = json.dumps(receipt).encode()
    #data = json.dumps(receipt)
    create_if_not_exists("client_side/", "receipts")
    create_if_not_exists("client_side/receipts/", sid)
    with open("client_side/receipts/{}/{}.bin".format(sid,"Auc" + receipt["idx"] + "_" + receipt["timestamp"]), "wb") as file:
        file.write(data)

def load_receipt(sid, name):
    with open("client_side/receipts/{}/{}".format(name, sid), "rb") as file:
        jay = json.loads(file.read().decode())
    print(str(jay))
    return jay


for slot in slots:
    serial_number = pkcs11.getTokenInfo(slot).to_dict()['serialNumber']

    session = pkcs11.openSession(slot)

    auc_client.generate_keys("client_side/users/", serial_number)

    #TODO Yank out the priv key aquire section of setup_connection.

    auc_client.setup_man_repo_conn(session)

    while (True):
        command = input("---\n"
                        "1) Criar auction\n"
                        "2) List Auctions\n"
                        "3) List Bids Of Auction\n"
                        "4) List Bids Of A User\n"
                        "5) Bid an Auction\n"
                        "6) Consult/Validate bid\n"
                        "7) Quit\n>")

        #Create Auction
        if command == "1":
            UDP_IP = '127.0.0.1'
            UDP_PORT = 5252
            sock = socket(AF_INET, SOCK_DGRAM)

            auc_name = input("Nome do item\n>")
            auc_descr = input("Descricao do item\n>")
            auc_type = input("Tipo de auction? 0/1 (English/Blind)\n>")
            auc_time_limit = float(input("Tempo limite em minutos\n>"))
            #auc_entity_limit = input("Limite de entidades a fazerem bids? \'n\'/\'N\' para 'não\'.\n>")
            #if auc_entity_limit not in ["n","N"]:
            #    auc_entity_limit = int(auc_entity_limit)

            #auc_entity_bid_limit = input("Limite de bids por entidade? \'n\'/\'N\' para \'não\'.'")
            #if auc_entity_bid_limit not in ["n","N"]:
            #    auc_entity_bid_limit = int(auc_entity_bid_limit)

            tup = generate_asym_pair()

            currentTime = datetime.datetime.now()

            request = {
                "author_id": serial_number,
                "name": auc_name,
                "type": auc_type,
                "current_time": currentTime,
                "time_limit": currentTime + datetime.timedelta(minutes=auc_time_limit),
                "description": auc_descr,
                "public_key": base64.encodestring(tup[1]).decode()
            }

            ciphered = cipher_operations().hybrid_cipher("create", serial_number, "Manager", request,
                                                         auc_client.pems["Manager"], auc_client.sessions["Manager"])
            comm().send_out(ciphered, MANAGER_ADDRESS, sock)

            data, address = sock.recvfrom(4096)
            idxmsg = json.loads(data)
            auction_details = cipher_operations().parse_valid_message(idxmsg, idxmsg["user_id"],
                                                                  auc_client.sessions[idxmsg["user_id"]],
                                                                  auc_client.private_key)

            auc_client.my_auction_pems[auction_details["idx"]] = tup

        #Listagem de todas as auctions
        elif command == "2":
            UDP_IP = '127.0.0.1'
            UDP_PORT = 1234

            sock = socket(AF_INET, SOCK_DGRAM)

            request = {"operation":"list"}

            ciphered = cipher_operations().hybrid_cipher("listOut", serial_number, "Repository", request,
                                                         auc_client.pems["Repository"],
                                                         auc_client.sessions["Repository"])
            comm().send_out(ciphered, REPOSITORY_ADDRESS, sock)

            data, address = sock.recvfrom(4096)
            message = json.loads(data)
            auction_list = cipher_operations().parse_valid_message(message, message["user_id"],
                                                                  auc_client.sessions[message["user_id"]],
                                                                  auc_client.private_key)
            print("---ACTIVE---")
            for x in auction_list["active"]:
                print("{}:\t{}".format(x, auction_list["active"][x]))
            print("---COMPLETE---")
            for x in auction_list["complete"]:
                print("{}:\t{}".format(x, auction_list["complete"][x]))

        #Listagem de bids de uma action
        elif command == "3":
            sock = socket(AF_INET, SOCK_DGRAM)

            auc_idx = input("Index da auction?\n>")
            request = {
                "idx": auc_idx
            }

            ciphered = cipher_operations().hybrid_cipher("aucBids", serial_number, "Repository", request,
                                                         auc_client.pems["Repository"],
                                                         auc_client.sessions["Repository"])
            comm().send_out(ciphered, REPOSITORY_ADDRESS, sock)


            data2, address2 = sock.recvfrom(4096)
            msg = json.loads(data2)
            auc_info = cipher_operations().parse_valid_message(msg, msg["user_id"],
                                                                  auc_client.sessions[msg["user_id"]],
                                                                  auc_client.private_key)
            if msg["requestType"] == "aucBids":
                print("---BIDS---")
                for x in auc_info["result"]:
                    print("Autor: \t{}\nBid:\t{}\n------\n".format(x[0], x[1]))
            else:
                print("No such index")


        #Listagem de bids por user
        elif command == "4":
            print("WIP")
        #Criar bid
        elif command == "5":
            sock = socket(AF_INET, SOCK_DGRAM)

            auc_idx = input("Índice da auction\n>")
            auc_newBid = float(input("Novo valor\n>"))


            signature = auc_client.sign_with_cc(session, bytes(utils().xor_2strs(str(auc_newBid), str(serial_number)).encode()))

            request = {"bid_value": auc_newBid,
                       "autor": serial_number,
                       "idx": auc_idx,
                       "signature": base64.encodestring(bytes(signature)).decode()
                       }

            ciphered = cipher_operations().hybrid_cipher("bid", serial_number, "Repository", request,
                                                         auc_client.pems["Repository"], auc_client.sessions["Repository"])
            comm().send_out(ciphered, REPOSITORY_ADDRESS, sock)

            while True:
                data, address = sock.recvfrom(4096)
                msg = json.loads(data)
                crypto_info = cipher_operations().parse_valid_message(msg, msg["user_id"],
                                                                      auc_client.sessions[msg["user_id"]],
                                                                      auc_client.private_key)
                if msg["requestType"] == "receipt":
                    # Get receipt
                    store_receipt(crypto_info, serial_number)
                    break
                else:
                    nbits = crypto_info["nbits"]
                    threshold = crypto_info["threshold"]
                    send_out = {"answer": cryptopuzzle(nbits, threshold)}
                    ciphered = cipher_operations().hybrid_cipher("bid", serial_number, "Repository", send_out,
                                                                 auc_client.pems["Repository"],
                                                                 auc_client.sessions["Repository"])
                    comm().send_out(ciphered, REPOSITORY_ADDRESS, sock)

        # View receipt and validate on prompt
        if command == "6":
            sock = socket(AF_INET, SOCK_DGRAM)

            list = os.listdir("client_side/receipts/{}".format(serial_number))
            for i, x in enumerate(list):
                print("{}:\t{}".format(i, x))
            try:
                idx = int(input("Command?\n>"))
                receipt = load_receipt(list[idx], serial_number)

                ciphered = cipher_operations().hybrid_cipher("bid_validate", serial_number, "Repository", receipt,
                                                             auc_client.pems["Repository"],
                                                             auc_client.sessions["Repository"])
                comm().send_out(ciphered, REPOSITORY_ADDRESS, sock)

                data, address = sock.recvfrom(4096)
                msg = json.loads(data)
                crypto_info = cipher_operations().parse_valid_message(msg, msg["user_id"],
                                                                      auc_client.sessions[msg["user_id"]],
                                                                      auc_client.private_key)
                print(crypto_info)

            except ValueError:
                continue

        #Quit
        if command == "7":
            break
