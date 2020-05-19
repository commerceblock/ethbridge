#!/usr/bin/env python3
import logging
import sys
from .test_framework.authproxy import JSONRPCException
from .connectivity import getoceand

class OceanWallet():
    def __init__(self, conf):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.ocean = getoceand(conf)
        self.key = conf["oceankey"]
        self.address = conf["oceanaddress"]

        #Check if the node wallet already has the deposit key before importing
        validate = self.ocean.validateaddress(self.address)
        have_va_addr = bool(validate["ismine"])
        watch_only = bool(validate["iswatchonly"])
        have_va_prvkey = have_va_addr and not watch_only

        rescan_needed = True

        if have_va_prvkey == False:
            try:
                self.ocean.importprivkey(self.key,"privkey",rescan_needed)
            except Exception as e:
                self.logger.error("{}\nFailed to import Ocean wallet private key".format(e))
                sys.exit(1)

            #Have just imported the private key so another rescan should be unnecesasary
            rescan_needed=False

        #Check if we still need to import the address given that we have just imported the private key
        validate = self.ocean.validateaddress(self.p2sh)
        have_va_addr = bool(validate["ismine"])
        if have_va_addr == False:
            ocean.importaddress(self.p2sh,"deposit",rescan_needed)
            validate = ocean.validateaddress(self.p2sh)

    def get_deposit_txs(self):
        deposit_txs = []
        #check that the deposit address has been imported, and if not import
        if self.ocean.getaccount(self.address) != "deposit":
            self.ocean.importaddress(self.address,"deposit")
        try:
            recieved = self.ocean.listreceivedbyaddress()
            for tx in recieved["txids"]:
                txin = self.ocean.gettransaction(tx)
                deposit_txs.append(txin)
            return deposit_txs
        except Exception as e:
            self.logger.warning("failed reissuance tx generation: {}".format(e))
            return None

    def get_sending_address(self, new_txs):
        new_txs_with_address = []
        #get the sending address
        #if there are more than 1 input, we take the first address
        #if the other input addresses as different, we print a log/warning
        try:
            for tx in new_txs:
                for inputs in tx["vin"]:
                    txin = self.ocean.getrawtransaction(inputs["txid"],1)
                    in_address = txin["vout"][inputs["n"]]["addresses"]["address"]




      
