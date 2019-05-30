import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class BidKnot:
    def __init__(self, bid, autor, signature, creation_date=datetime.datetime.now()):
        self.bid = bid
        self.autor = autor
        self.signature = signature
        self.creation_date = creation_date
        self.nextKnot = None
        self.digest = None

    def addKnot(self, nextKnot):
        if not self.nextKnot:
            self.nextKnot = nextKnot
        else:
            self.nextKnot.addKnot(nextKnot)

    def getLast(self):
        if not self.nextKnot:  # if not (False if == None, True if != None)
            return self
        else:
            return self.nextKnot.getLast()


    def getBidList(self):
        #TODO List the bids!
        if not self.nextKnot:  # if not (False if == None, True if != None)
            yield self.nextKnot
        else:
            yield self.nextKnot
            return self.nextKnot.getBidList()

    def count(self, i=0):
        if not self.nextKnot:
            return i + 1
        else:
            return self.nextKnot.count(i + 1)

    def next(self):
        return self.nextKnot

    def calculate_digest(self,parent_digest=None):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(self.creation_date).encode("utf-8")))
        digest.update(bytes(str(self.autor).encode("utf-8")))
        if parent_digest:
            digest.update(parent_digest)

        return digest.finalize()

    def set_digest(self,dad_digest):
        self.digest = self.calculate_digest(dad_digest)

    def verify_integrity(self, dad_digest):
        calculated_digest = self.calculate_digest(parent_digest=dad_digest)
        if self.digest != calculated_digest:
            return False
        elif self.next():
            return self.next().verify_integrity(self.digest)
        return calculated_digest


    def __str__(self):
        return str(self.__dict__)

