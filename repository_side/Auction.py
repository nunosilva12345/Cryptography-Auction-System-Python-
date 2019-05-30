#TODO Onde fica o base price e o tipo de auction? Comeca do 0?

import datetime

from repository_side.BidKnot import BidKnot

class Auction:
    def __init__(self, idx, auction_type, name, usn, current_time, time_limit, description, max_size):  #rise_up e a variavel/argumento que trata do valor que a nova auction deve ter a mais que a anterior
        self.idx = idx
        self.auction_type = auction_type
        self.name = name
        self.usn = usn
        self.current_time = current_time
        self.time_limit = time_limit
        self.description = description
        self.max_size = max_size

        self.bids = BidKnot(0, "root", "root")   #linked_list que comeca com um root
        self.bids.set_digest(dad_digest=None)

        self.last_bid_pointer = self.bids

    def hasEnded(self):
        if datetime.datetime.strptime(self.time_limit, "%Y-%m-%d %H:%M:%S.%f") < datetime.datetime.now() \
                or self.bids.count() > self.max_size:
            return True
        else:
            return False

    def provideDetails(self):
        return str(self.__dict__)

    def getBids(self):
        return self.bids

    def currentWinner(self):
        return str(self.bids.getLast().__dict__)

    def get_bid_count(self):
        return self.bids.count()

    def addBid(self, bid):
        print()
        last_bid = self.bids.getLast()  #get the most recent bid

        print("NEW_BID:", bid.bid)
        print("LAST_BID:" , last_bid)

        bid.set_digest(dad_digest=self.bids.getLast().digest)
        last_bid.nextKnot = bid

        self.last_bid_pointer = bid
        print("NEW_VALUE:", bid.bid)
        return bid


