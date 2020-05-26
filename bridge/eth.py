#!/usr/bin/env python3
from web3 import Web3, HTTPProvider
import logging
import sys
from .test_framework.authproxy import JSONRPCException

class EthWallet():
    def __init__(self, conf):
        self.w3 = Web3(Web3.HTTPProvider(conf["id"]))
        self.logger = logging.getLogger(self.__class__.__name__)
        self.key = conf["ethkey"]
        self.contract = conf["contract"]

    def get_burn_txs(self, conf):
        deposit_txs = []
        #get all transactions on ethereum that have been sent to the burn address (to peg back into Ocean)
        try:

            return deposit_txs
        except Exception as e:
            self.logger.warning("failed get eth burn transactions: {}".format(e))
            return None

    def get_sending_address(self, new_txs):
        new_txs_with_address = []
        #get the sending address
        try:
            #search through new eth txs and add the sending address to each entry
            return new_txs_with_address
        except Exception as e:
            self.logger.warning("failed get sending address ocean: {}".format(e))
            return None

    def check_deposits(self, conf, new_txs):
        #check that the new transactions recieved have not been previously minted from the eth contract
        return new_txs

    def mint_tokens(self, conf, payment_list):
        minted_txs = []
        try:
            for payment in payment_list:
                #mint the required tokens
                pass
            return minted_txs
        except Exception as e:
            self.logger.warning("failed ocean payment tx generation: {}".format(e))
            return None








      
