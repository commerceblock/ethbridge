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

class Watcher(DaemonThread):
    def __init__(self, conf, signer=None):
        super().__init__()
        self.conf = conf
        self.default_interval = INTERVAL_DEFAULT if "interval" not in conf else conf["interval"]
        self.interval = self.default_interval
        self.logger = logging.getLogger(self.__class__.__name__)

        self.signer = signer
        self.ocean = OceanWallet(conf)
        self.eth = EthWallet(conf)

    def run_ocean(self):
        #get all addresses and amounts of all transactions received to the deposit address
        new_txs = self.ocean.get_deposit_txs()

        if not new_txs:
            return

        #get address that the deposit has been sent from - required for checking eth deposits
        new_txs = self.ocean.get_sending_address(new_txs)

        #check to see if any have not already been minted
        new_txs = self.eth.check_deposits(new_txs)

        if new_txs:
            for tx in new_txs:
                self.logger.info("New Ocean deposit: "+tx["txid"]+" Sending address: "+str(tx["sendingaddress"])+" Amount: "+ str(tx["pegamount"]))
            #for each verified new deposit transaction, mint the contract tokens on Ethereum to the sending address
            mint_txs = self.eth.mint_tokens(new_txs)
        else:
            mint_txs=[]

        if mint_txs:
            for tx, receipt in mint_txs:
                self.logger.info("Mint Eth tokens: "+tx["txid"]+" Address: "+str(tx["sendingaddress"])+" Amount: " + str(tx["pegamount"])  + " Receipt: " + str(receipt))
                

    def rpc_retry(self, rpc_func, *args):
        for i in range(5):
            try:
                return rpc_func(*args)
            except Exception as e:
                self.logger.warning("{}\nReconnecting to client...".format(e))
                self.ocean = getoceand(self.conf)
        self.logger.error("Failed reconnecting to client")
        self.stop()

    def run_eth(self):
        #get all addresses and amounts of all transactions received to the deposit address
        received_txs = self.eth.get_burn_txs()

        if not received_txs:
            return
            
        #check to see if any have not already been minted
        new_txs = self.ocean.check_deposits(received_txs)
        #new_txs = self.ocean.get_sending_address(new_txs)
        for tx in new_txs:
            self.logger.info("New Eth deposit: " + tx.transactionHash + " Eth sender address: " + tx.from_ + " Ocean recipient address: "+tx.to +" Amount: "+str(tx.amount))
        #for each verified new deposit transaction, mint the contract tokens on Ethereum to the sending address
        self.ocean.send_tokens(new_txs)
                    
    def run(self):
        while not self.stopped():
            sleep(self.interval - time() % self.interval)
            start_time = int(time())
            self.run_ocean()
            self.run_eth()
            elapsed_time = time() - start_time
            sleep(self.interval / 2 - (elapsed_time if elapsed_time < self.interval / 2 else 0))
