import base64
import datetime
import json
import os
import secrets
from _socket import socket, AF_INET, SOCK_DGRAM

from cryptography import x509, exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding as padding_sym
from cryptography.hazmat.primitives.asymmetric import padding as padding_asym

from certificate_validator.Certificate import Certificate_Knot
from  message_module.ExchangeMessages import Communication as comm
from  message_module.ExchangeMessages import Cripthography as cipher_operations


#AuctionManager.pkey_dict[sender][1]-->encrypt_assymetric_public
#AuctionManager.local_private_key-->decrypt_assymetri_private

def datetime_to_string_conv(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()


def establish_connection_client(address):
    challenge = secrets.token_bytes(32)
    json_message = {"responseType": "challenge",
                    "challenge": base64.encodestring(challenge).decode()}
    jay = json.dumps(json_message)
    print(str(json_message))
    sock.sendto(jay.encode("utf-8"), address)

    data, address = sock.recvfrom(4096)

    print(str(data))
    response = json.loads(data)

    clientSign = base64.b64decode(response["signature"].encode())
    clientCert = base64.decodestring(response["certificate"].encode())
    # Aquire signature + public key certificate and check if challenge
    goodcert = x509.load_der_x509_certificate(clientCert, backend=default_backend())

    #TODO Check what's wrong here!!!
    Certificate_Knot(clientCert).build_certificate_path()

    pub_key = goodcert.public_key()

    # InvalidSignature will only trigger "if the bytes provided to update do not match the
    #   signature or the signature does not match the public key."
    try:
        pub = pub_key.verify(
            signature=bytes(clientSign),
            data=challenge,
            padding=padding_asym.PKCS1v15(),
            algorithm=hashes.SHA256()
        )
        # This person is legitimate
        print("This user's alright!")
    except (exceptions.InvalidSignature):
        # It failed, leave him to time out and get out of this part
        print("Go away pesky person.")
        return

    # Now we answer his challenge by encrypting it with private key. User will check it with the previously aquired server public key
    challenge = base64.decodestring(response["challenge2"].encode())
    signature = auc_manager.local_private_key.sign(
        challenge,
        padding_asym.PSS(
            mgf=padding_asym.MGF1(hashes.SHA256()),
            salt_length=padding_asym.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Challenge: ", challenge)
    print("Signature: ", signature)

    json_message = {"responseType": "challenge",
                    "signature": base64.encodestring(signature).decode()
                    }
    jay = json.dumps(json_message)
    print(str(json_message))
    sock.sendto(jay.encode("utf-8"), address)

    data, address = sock.recvfrom(4096)
    response = json.loads(data)

    decoded_key = base64.b64decode(response["key"])

    pub = serialization.load_pem_public_key(
        decoded_key,
        backend=default_backend()
    )

    # TODO Change the bits
    secr = secrets.token_bytes(16)
    auc_manager.pkey_dict[response["id"]] = (pub, secr)
    print("USER {} ADDED".format(response["id"]))



    cipher_secret = pub.encrypt(
        secr,
        padding_asym.OAEP(
            mgf=padding_asym.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    cipher_secret = base64.encodestring(cipher_secret)

    json_message = {"responseType": "ACK",
                    "secret": cipher_secret.decode('ascii')}
    jay = json.dumps(json_message)
    sock.sendto(jay.encode("utf-8"), address)


class AuctionManager:
    def __init__(self):
        with open("manager_side/publicPEM.pem", "rb") as key_file:
            self.local_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            print(str(self.local_public_key) + "\nLoaded!")

        with open("manager_side/privatePEM.pem", "rb") as key_file:
            self.local_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=b'manager',
                backend=default_backend()
            )
            print(str(self.local_private_key) + "\nLoaded!")

        with open("manager_side/repositoryPublicPEM.pem", "rb") as key_file:
            self.repo_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            print(str(self.repo_public_key) + "\nLoaded!")

        self.certs = set()
        self.pkey_dict = {}
        self.man_repo_secret = None
        self.auc_restrictions = {}

    def add_cert(self,cert):
        certificate = x509.load_der_x509_certificate(cert, backend=default_backend())
        self.certs.add(certificate)
        print(str(self.certs))

    def create_auction(self, auction, maxbids=-1, auctionType=0):
        #sock = socket(AF_INET, SOCK_DGRAM)
        #request = {"requestType": "create", "name": name, "usn": usn, "current_time": current_time,
        #           "time_limit": time_limit, "description": description, "max_size": max_size}
        #jay = json.dumps(request)
        #sock.sendto(jay.encode(encoding="utf-8"), REPOSITORY_ADDRESS)
        pass


        #TODO Handle Auction Max Size

    def validate_bid(self, bid):
        print(type(bid["idx"]))
        restrictions = self.auc_restrictions[bid["idx"]]
        if restrictions["type"] == "English":
            print("Is english")
            if int(bid["bid_value"]) > restrictions["last_max"]:
                self.auc_restrictions[bid["idx"]]["last_max"] = int(bid["bid_value"])
                #TODO
                bid["autor"] = base64.encodestring(cipher_operations().encrypt_assymetric_public(bid["autor"].encode(), restrictions["key"])).decode()
                return bid
            else:
                return None
        else:
            print("Is blind")
            bid["bid_value"] = base64.encodestring(cipher_operations().encrypt_assymetric_public(bid["bid_value"].encode(), restrictions["key"])).decode()
            return bid




UDP_IP = '127.0.0.1'
UDP_PORT = 5252

REPOSITORY_ADDRESS = ('127.0.0.1', 1234)

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))
auc_manager = AuctionManager()


def establish_connection_repo(ADDRESS):
    secret = secrets.token_bytes(32)
    print(secret)
    enc_secret = auc_manager.repo_public_key.encrypt(
        secret,
        padding_asym.OAEP(
            mgf=padding_asym.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print()
    tobesent = {
        "requestType": "hello_repository",
        "key": base64.encodestring(enc_secret).decode()
    }
    comm().send_out(tobesent, ADDRESS, sock)

    data, server = sock.recvfrom(4096)

    response = json.loads(data)

    print("Response received:\t{}".format(str(response)))
    if response["responseType"] == "hello_manager":
        print("All is right with the world.")
        auc_manager.man_repo_secret = secret

establish_connection_repo(REPOSITORY_ADDRESS)

while True:
    (data, address) = sock.recvfrom(4096)
    print(data)



    #TODO Encriptar cert com public key de manager
    msg = json.loads(data)

    #Authenticate user and establish connection (secrets + public keys)
    if msg["requestType"] == "challenge_please":
        establish_connection_client(address)

    if msg["requestType"] == "bid_validate":
        bid= cipher_operations().parse_valid_message(msg, msg["user_id"], auc_manager.man_repo_secret, auc_manager.local_private_key)
        new_bid = auc_manager.validate_bid(bid)

        ciphered = cipher_operations().hybrid_cipher("create", "Manager", "Repository", new_bid,
                                                     auc_manager.repo_public_key, auc_manager.man_repo_secret)
        comm().send_out(ciphered, REPOSITORY_ADDRESS, sock)

    if msg["requestType"] == "create":
        CLIENT_ADDRESS = address
        #Get auction values
        auction = cipher_operations().parse_valid_message(msg, msg["user_id"], auc_manager.pkey_dict[msg["user_id"]][1], auc_manager.local_private_key)


        client_pub_key = base64.decodestring(auction["public_key"].encode())
        print("a")
        #TODO Special bid ops a adicionar à auction

        #Send to repository
        ciphered = cipher_operations().hybrid_cipher("create", "Manager", "Repository", auction, auc_manager.repo_public_key, auc_manager.man_repo_secret)
        comm().send_out(ciphered, REPOSITORY_ADDRESS, sock)


        #Receive auction idx to store the key/iv and other fields
        (data, address) = sock.recvfrom(4096)
        jay = json.loads(data)

        received = cipher_operations().parse_valid_message(jay, jay["user_id"], auc_manager.man_repo_secret, auc_manager.local_private_key)


        #English or Blind, store configs to idx
        print(type(received["idx"]))
        if auction["type"] == "0":
            auc_manager.auc_restrictions[str(received["idx"])] = {"type": "English",
                                                             "key" : serialization.load_pem_public_key(client_pub_key, backend=default_backend()),
                                                             "last_max" : 0
                                                             }
        else:
            auc_manager.auc_restrictions[str(received["idx"])] = {"type": "Blind",
                                                             "key" : serialization.load_pem_public_key(client_pub_key, backend=default_backend()),
                                                             "last_max" : 0
                                                             }

        message4user = {"responseType": "ACK",
                        "idx": received["idx"]}

        # Send to repository
        ciphered2 = cipher_operations().hybrid_cipher("create2", "Manager", "Repository", auction,
                                                     auc_manager.repo_public_key, auc_manager.man_repo_secret)
        comm().send_out(ciphered2, REPOSITORY_ADDRESS, sock)

        #Send to client
        ciphered2 = cipher_operations().hybrid_cipher("create02", "Manager", msg["user_id"], message4user,
                                                     auc_manager.pkey_dict[msg["user_id"]][0],
                                                     auc_manager.pkey_dict[msg["user_id"]][1])
        comm().send_out(ciphered2, CLIENT_ADDRESS, sock)
