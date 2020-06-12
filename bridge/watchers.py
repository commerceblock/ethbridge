#!/usr/bin/env python3
from web3 import Web3, HTTPProvider
import json
import sys
import logging
from time import sleep, time
from hashlib import sha256 as _sha256
from .daemon import DaemonThread
from .ocean import OceanWallet
from .eth import EthWallet
from .test_framework.authproxy import JSONRPCException
from .connectivity import getoceand

INTERVAL_DEFAULT = 60

class OceanWatcher(DaemonThread):
    def __init__(self, conf, signer=None):
        super().__init__()
        self.conf = conf
        self.default_interval = INTERVAL_DEFAULT if "interval" not in conf else conf["interval"]
        self.interval = self.default_interval
        self.logger = logging.getLogger(self.__class__.__name__)

        self.signer = signer
        self.ocean = OceanWallet(conf)
        self.eth = EthWallet(conf)

    def run(self):
        while not self.stopped():
            sleep(self.interval - time() % self.interval)
            start_time = int(time())

            #get all addresses and amounts of all transactions received to the deposit address
            received_txs = self.ocean.get_deposit_txs()
            print("ocean watcher - received_txs : {}".format(len(received_txs)))
            print("checking eth deposits...")
            #check to see if any have not already been minted
            new_txs = self.eth.check_deposits(received_txs)
            print("ocean watcher - new_txs: {}".format(len(new_txs)))
            #get address that the deposit has been sent from
            new_txs = self.ocean.get_sending_address(new_txs)
            print("ocean watcher - new_txs with sending address: {}".format(len(new_txs)))
            if new_txs:
                for tx in new_txs:
                    print("tx: {}".format(tx))
                    self.logger.info("New Ocean deposit: "+tx["txid"]+" Sending address: "+str(tx["sendingaddress"])+" Amount: "+str(tx["amount"]))
                #for each verified new deposit transaction, mint the contract tokens on Ethereum to the sending address
                mint_txs = self.eth.mint_tokens(new_txs)
                mint_txs = None
            else:
                mint_txs=[]

            if mint_txs:
                for tx in mint_txs:
                    self.logger.info("Mint Eth tokens: "+tx["txid"]+" Address: "+tx["address"]+" Amount: "+str(tx["amount"]))
                
            elapsed_time = time() - start_time
            sleep(self.interval / 2 - (elapsed_time if elapsed_time < self.interval / 2 else 0))

    def rpc_retry(self, rpc_func, *args):
        for i in range(5):
            try:
                return rpc_func(*args)
            except Exception as e:
                self.logger.warning("{}\nReconnecting to client...".format(e))
                self.ocean = getoceand(self.conf)
        self.logger.error("Failed reconnecting to client")
        self.stop()


class EthWatcher(DaemonThread):
    def __init__(self, conf, signer=None):
        super().__init__()
        self.conf = conf
        self.default_interval = INTERVAL_DEFAULT if "interval" not in conf else conf["interval"]
        self.interval = self.default_interval
        self.logger = logging.getLogger(self.__class__.__name__)

        self.signer = signer
        self.ocean = OceanWallet(conf)
        self.eth = EthWallet(conf)



    def run(self):
        while not self.stopped():
            sleep(self.interval - time() % self.interval)
            start_time = int(time())

            #get all addresses and amounts of all transactions recieved to the deposit address
            recieved_txs = self.eth.get_burn_txs()
            #check to see if any have not already been minted
            new_txs = self.ocean.check_deposits(self.conf, recieved_txs)
            new_txs = self.ocean.get_sending_address(new_txs)
            for tx in new_txs:
                self.logger.info("New Ocean deposit: "+tx["txid"]+" Sending address: "+tx["address"]+" Amount: "+str(tx["amount"]))
            #for each verified new deposit transaction, mint the contract tokens on Ethereum to the sending address
            not_whitelisted = self.ocean.send_tokens(new_txs)

            if len(not_whitelisted) > 0:
                sent_back = self.eth.mint_tokens(self.conf,not_whitelisted)

                for tx in sent_back:
                    self.logger.info("Returned Eth tokens: "+tx["txid"]+" Address: "+tx["address"]+" Amount: "+str(tx["amount"]))
                
            elapsed_time = time() - start_time
            sleep(self.interval / 2 - (elapsed_time if elapsed_time < self.interval / 2 else 0))


