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
        validate = self.ocean.validateaddress(self.address)
        have_va_addr = bool(validate["ismine"])
        if have_va_addr == False:
            ocean.importaddress(self.p2sh,"deposit",rescan_needed)
            validate = ocean.validateaddress(self.addresses)

    def get_deposit_txs(self):
        deposit_txs = []
        try:
            recieved = self.ocean.listreceivedbyaddress()
            for raddress in recieved:
                if raddress["address"] == self.address:
                    for tx in raddress["txids"]:
                        txin = self.ocean.getrawtransaction(tx,1)
                        deposit_txs.append(txin)
            return deposit_txs
        except Exception as e:
            self.logger.warning("failed to get ocean deposit transactions: {}".format(e))
            return None

    def get_sending_address(self, new_txs):
        new_txs_with_address = []
        #get the sending address
        #if there are more than 1 input, we take the first address
        #if the other input addresses are different, we print a log/warning
        try:
            for tx in new_txs:
                addresses = []
                for inputs in tx["vin"]:
                    txin = self.ocean.getrawtransaction(inputs["txid"],1)
                    for vout in txin["vout"]:
                        if vout["n"] == inputs["vout"]: in_address = vout["scriptPubKey"]["addresses"][0]
                    addresses.append(in_address)
                if len(set(addresses)) != 1:
                    self.logger.warning("More than one address as input to: "+str(tx["txid"]))
                tx["sendingaddress"] = addresses[0]
                new_txs_with_address.append(tx)
            return new_txs_with_address
        except Exception as e:
            self.logger.warning("failed get sending address ocean: {}".format(e))
            return None

    def check_deposits(self, conf, new_txs):
        #check that the new transactions recieved have not been previously paid out from the Ocean deposit wallet
        return new_txs

    def send_tokens(self, payment_list):
        non_whielisted = []
        try:
            for payment in payment_list:
                is_whitelisted = self.querywhitelist(payment["address"])
                if is_whitelisted:
                    txid = self.ocean.sendanytoaddress(payment["address"],payment["amount"])
                else:
                    self.logger.warning("Ocean payment: "+payment["address"]+" from Eth TxID "+payment["txid"]+" not whitelisted")
                    non_whielisted.append(payment)
        except Exception as e:
            self.logger.warning("failed ocean payment tx generation: {}".format(e))
            return None
        return non_whielisted








      
