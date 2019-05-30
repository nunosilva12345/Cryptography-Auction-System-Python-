#Recebe comando de listar auctions do cliente
#Manager envia msgs para editar auctions
import base64
import datetime, json, os, pickle, re, time
import random
import secrets
from _socket import socket, AF_INET, SOCK_DGRAM
from threading import Thread

from cryptography import exceptions, x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from message_module.Cryptopuzzle import calc_result, check_crypto
from repository_side.Auction import Auction
from repository_side.BidKnot import BidKnot
from message_module.ExchangeMessages import Communication as comm
from message_module.ExchangeMessages import Cripthography as cipher_operations

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
    pub_key = goodcert.public_key()

    # InvalidSignature will only trigger "if the bytes provided to update do not match the
    #   signature or the signature does not match the public key."
    try:
        pub = pub_key.verify(
            signature=bytes(clientSign),
            data=challenge,
            padding=padding.PKCS1v15(),
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
    signature = auction_rep.local_private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
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
    auction_rep.pkey_dict[response["id"]] = (pub, secr)
    print("USER {} ADDED".format(response["id"]))



    cipher_secret = pub.encrypt(
        secr,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher_secret = base64.encodestring(cipher_secret)

    json_message = {"responseType": "ACK",
                    "secret": cipher_secret.decode('ascii')}
    jay = json.dumps(json_message)
    sock.sendto(jay.encode("utf-8"), address)

def datetime_to_string_conv(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()



class AuctionRepository(Thread):
    def __init__(self):
        self.pkey_dict = {}
        with open("repository_side/publicPEM.pem", "rb") as key_file:
            self.local_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            print(str(self.local_public_key) + "\nLoaded!")

        with open("repository_side/privatePEM.pem", "rb") as key_file:
            self.local_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=b'repository',
                backend=default_backend()
            )
            print(str(self.local_private_key) + "\nLoaded!")

        with open("repository_side/managerPublicPEM.pem", "rb") as key_file:
            self.manager_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            print(str(self.manager_public_key) + "\nLoaded!")


        self.idx = len(os.listdir("repository_side/auc_active")) + len(os.listdir("repository_side/auc_complete"))
        Thread.__init__(self)
        # guarda lista de todas auction
        # e o cliente copmunica com repositorio para criar e terminar auctions

    def run(self):
        while(True):
            time.sleep(1)
            fileList = os.listdir("repository_side/auc_active")
            regex = re.compile("auction.*\.bin")
            correctFiles = list(filter(regex.search, fileList))
            for correctFile in correctFiles:
                if not self.Verify_Integrity(correctFile):
                    print("WARNING: {} HAS FAULTY INTEGRITY!".format(correctFile))
                if self.Verify_TimeOut(correctFile):
                    print("{} has ended".format(correctFile))
                    fileAct = open("repository_side/auc_active/" + correctFile, "rb")
                    fileCmp = open("repository_side/auc_complete/" + correctFile, "wb")
                    fileCmp.write(fileAct.read())
                    fileAct.close()
                    fileCmp.close()
                    os.remove("repository_side/auc_active/" + correctFile)

    def Generate_Auction_From_File(self, file):
        openedFile = open(file, "rb")

        auc = pickle.load(openedFile)

        return auc

    def Create_Auction(self, type, name, usn, current_time, time_limit, description, max_size):
        object_auction = Auction(self.idx, type, name, usn, current_time, time_limit, description, max_size)

        file = open("repository_side/auc_active/auction" + str(self.idx) + ".bin", "wb")

        pickle.dump(object_auction, file)

        file.close()

        self.idx = self.idx + 1
        return self.idx - 1

    def Recreate_Auction(self, auction, idx):

        file = open("repository_side/auc_active/auction{}.bin".format(idx), "wb")
        pickle.dump(auction,file)
        file.close()

    def Verify_TimeOut(self, filename):
        aquired = self.Generate_Auction_From_File("repository_side/auc_active/{}".format(filename))
        if datetime.datetime.strptime(aquired.time_limit, "%Y-%m-%d %H:%M:%S.%f") < datetime.datetime.now():
            print("{} has timed out.".format(filename))
            return True
        else:
            print("{} has not timed out yet...".format(filename))
            return False

    def Verify_Integrity(self, filename):
        aquired = self.Generate_Auction_From_File("repository_side/auc_active/{}".format(filename))
        print("Verified integrity " , aquired.bids.verify_integrity(dad_digest=None))
        print("Last bid digest" , aquired.bids.getLast().digest)
        if aquired.bids.verify_integrity(dad_digest=None) == aquired.last_bid_pointer.digest:
            print("Bid integrity OK!")
            return True
        else:
            print("Bid integrity NOT OK THIS AUCTION IS COMPROMISED")
            return False

    def Create_Bid(self, bid_value, autor, signature, idx):
        requestedAuc = self.Generate_Auction_From_File("repository_side/auc_active/auction{}.bin".format(idx))
        if requestedAuc:
            new_bid = BidKnot(bid_value, autor, signature)
            added_bid = requestedAuc.addBid(new_bid)
            self.Recreate_Auction(requestedAuc, idx)
            if (added_bid):
                print("Bid of value {} added to idx {}".format(bid_value, idx))
                return added_bid

    def list_all_auctions(self):
        output = {}
        active = {}


        for x in os.listdir("repository_side/auc_active"):
            aquired = self.Generate_Auction_From_File("repository_side/auc_active/{}".format(x))
            active[aquired.idx] = aquired.name
        complete = {}
        for x in os.listdir("repository_side/auc_complete"):
            aquired = self.Generate_Auction_From_File("repository_side/auc_complete/{}".format(x))
            complete[aquired.idx] = aquired.name

        print(active)
        print(complete)

        output["active"] = active
        output["complete"] = complete
        return output


UDP_IP = '127.0.0.1'
UDP_PORT = 1234

sock = socket(AF_INET, SOCK_DGRAM)
sock.settimeout(1000 * 60 * 60)
sock.bind((UDP_IP, UDP_PORT))

MANAGER_ADDRESS = ('127.0.0.1', 5252)

auction_rep = AuctionRepository()
auction_rep.setName("RepoThread")
auction_rep.start()




def accept_manager(address, encoded_asym_encrypted_key):
    decoded_key = base64.decodestring(encoded_asym_encrypted_key.encode())
    key = auction_rep.local_private_key.decrypt(
        decoded_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    auction_rep.pkey_dict["Manager"] = [auction_rep.manager_public_key, key]
    tobesent = {"responseType": "hello_manager"}
    comm().send_out(tobesent, address, sock)


while True:
    (data, address) = sock.recvfrom(4096)
    msg = json.loads(data)
    print("NEW HAPPENING:\n", msg)

    if msg["requestType"] == "challenge_please":
        establish_connection_client(address)

    if msg["requestType"] == "hello_repository":
        accept_manager(address, msg["key"])


    if msg["requestType"] == "create":

        print("a")
        auction = cipher_operations().parse_valid_message(msg, msg["user_id"], auction_rep.pkey_dict[msg["user_id"]][1], auction_rep.local_private_key)
        print("2")
        type = auction["type"]
        name = auction["name"]
        current_time = auction["current_time"]
        time_limit = auction["time_limit"]
        description = auction["description"]
        usn = auction["author_id"]
        index = auction_rep.Create_Auction(type, name, usn, current_time, time_limit, description, -1)

        #Tell manager you got the auction and send the index of said auction
        to_manager = {
            "requestType": "ACK",
            "idx":  index
        }

        result = cipher_operations().hybrid_cipher("create", "Repository", msg["user_id"], to_manager,
                                                   auction_rep.pkey_dict["Manager"][0],
                                                   auction_rep.pkey_dict["Manager"][1])
        comm().send_out(result, address, sock)

        (data, address) = sock.recvfrom(4096)
        aquired = json.loads(data)
        print("A-OK")


    if msg["requestType"] == "bid":
        bid = cipher_operations().parse_valid_message(msg, msg["user_id"], auction_rep.pkey_dict[msg["user_id"]][1], auction_rep.local_private_key)
        print(bid)

        auction = auction_rep.Generate_Auction_From_File("repository_side/auc_active/auction{}.bin".format(bid["idx"]))


        #Cryptopuzzle goes here
        while True:
            arg = random.randint(4,6)

            message = {"threshold": arg,
                       "nbits": 32 + auction.get_bid_count()}
            result = cipher_operations().hybrid_cipher("solve_crypto", "Repository", msg["user_id"], message,
                                                       auction_rep.pkey_dict[msg["user_id"]][0],
                                                       auction_rep.pkey_dict[msg["user_id"]][1])
            comm().send_out(result, address, sock)

            data, address = sock.recvfrom(4096)
            msg = json.loads(data)
            result = cipher_operations().parse_valid_message(msg, msg["user_id"],
                                                              auction_rep.pkey_dict[msg["user_id"]][1],
                                                              auction_rep.local_private_key)
            try:
                if check_crypto(result["answer"], arg):
                    print("CORRECT ANSWER")
                    break
            except:
                continue

        #Crypto ends here
        #Manager validation starts here
        result = cipher_operations().hybrid_cipher("bid_validate", "Repository", msg["user_id"], bid,
                                                   auction_rep.pkey_dict["Manager"][0],
                                                   auction_rep.pkey_dict["Manager"][1])
        comm().send_out(result, MANAGER_ADDRESS, sock)

        (data2, address2) = sock.recvfrom(4096)
        try:
            received= json.loads(data2)
            bid = cipher_operations().parse_valid_message(received, received["user_id"], auction_rep.pkey_dict[received["user_id"]][1],
                                                          auction_rep.local_private_key)
            print(bid)
        except:
            print("Wasn't a good bid")
            continue
        #Manager validation ends here


        bid_added = auction_rep.Create_Bid(bid["bid_value"], bid["autor"], bid["signature"], bid["idx"])


        if bid_added:
            signature = auction_rep.local_private_key.sign(
                bid_added.digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("An OK bid was added!")
            receipt = {
                "timestamp" : bid_added.creation_date,
                "idx": bid["idx"],
                "bid_value": bid_added.bid,
                "repository_signature": signature,
                "author_signature": bid_added.autor
            }
            result = cipher_operations().hybrid_cipher("receipt", "Repository", msg["user_id"], receipt,
                                                       auction_rep.pkey_dict[msg["user_id"]][0],
                                                       auction_rep.pkey_dict[msg["user_id"]][1])
            comm().send_out(result, address, sock)

    if msg["requestType"] == "listOut":
        message = cipher_operations().parse_valid_message(msg, msg["user_id"], auction_rep.pkey_dict[msg["user_id"]][1],
                                                          auction_rep.local_private_key)
        if message["operation"] == "list":
            out = auction_rep.list_all_auctions()

            result = cipher_operations().hybrid_cipher("receipt", "Repository", msg["user_id"], out,
                                                       auction_rep.pkey_dict[msg["user_id"]][0],
                                                       auction_rep.pkey_dict[msg["user_id"]][1])
            comm().send_out(result, address, sock)


    if msg["requestType"] == "aucBids":
        message = cipher_operations().parse_valid_message(msg, msg["user_id"], auction_rep.pkey_dict[msg["user_id"]][1],
                                                          auction_rep.local_private_key)
        index = message["idx"]

        auction = None
        try:
            auction = auction_rep.Generate_Auction_From_File("repository_side/auc_active/auction{}.bin".format(index))
        except FileNotFoundError:
            print("\'{}\' not in actives..".format(index))
        if not auction:
            try:
                auction = auction_rep.Generate_Auction_From_File(
                    "repository_side/auc_complete/auction{}.bin".format(index))
            except FileNotFoundError:
                print("\'{}\' not in complete auctions..".format(index))
        if not auction:
            message = {"message": "Not found"}
            result = cipher_operations().hybrid_cipher("aucBids_failed", "Repository", msg["user_id"], message,
                                                       auction_rep.pkey_dict[msg["user_id"]][0],
                                                       auction_rep.pkey_dict[msg["user_id"]][1])
            comm().send_out(result, address, sock)
        else:
            list = []
            iterator = auction.bids
            while iterator.nextKnot:
                iterator = iterator.next()
                list.append([iterator.autor, iterator.bid])

            return_message = {"result": list}
            result = cipher_operations().hybrid_cipher("aucBids", "Repository", msg["user_id"], return_message,
                                                       auction_rep.pkey_dict[msg["user_id"]][0],
                                                       auction_rep.pkey_dict[msg["user_id"]][1])
            comm().send_out(result, address, sock)

    if msg["requestType"] == "bid_validate":
        message = cipher_operations().parse_valid_message(msg, msg["user_id"], auction_rep.pkey_dict[msg["user_id"]][1],
                                                          auction_rep.local_private_key)

        index = message["idx"]

        auction = None
        try:
            auction = auction_rep.Generate_Auction_From_File("repository_side/auc_active/auction{}.bin".format(index))
        except FileNotFoundError:
            print("\'{}\' not in actives..".format(index))
        if not auction:
            try:
                auction = auction_rep.Generate_Auction_From_File(
                    "repository_side/auc_complete/auction{}.bin".format(index))
            except FileNotFoundError:
                print("\'{}\' not in complete auctions..".format(index))
        if not auction:
            errormessage = {"message": "Auction not found"}
            result = cipher_operations().hybrid_cipher("aucBids_failed", "Repository", msg["user_id"], errormessage,
                                                       auction_rep.pkey_dict[msg["user_id"]][0],
                                                       auction_rep.pkey_dict[msg["user_id"]][1])
            comm().send_out(result, address, sock)
        else:
            flag = False
            iterator = auction.bids
            while iterator.nextKnot:
                iterator = iterator.next()
                if iterator.creation_date == message["timestamp"] and    \
                    iterator.bid == message["bid_value"] and iterator.signature == message["author_signature"]:
                    #TODO Incomplete! What if the client tampered with this?
                    print("Valid!")
                    flag = True
                    answer = {"message": "Valid receipt!"}
                    result = cipher_operations().hybrid_cipher("receipt_return", "Repository", msg["user_id"],
                                                               answer,
                                                               auction_rep.pkey_dict[msg["user_id"]][0],
                                                               auction_rep.pkey_dict[msg["user_id"]][1])
                    comm().send_out(result, address, sock)
                    break
                else:
                    continue

            if not flag:
                answer = {"message": "Bid not found.."}
                result = cipher_operations().hybrid_cipher("receipt_return", "Repository", msg["user_id"],
                                                           answer,
                                                           auction_rep.pkey_dict[msg["user_id"]][0],
                                                           auction_rep.pkey_dict[msg["user_id"]][1])
                comm().send_out(result, address, sock)
