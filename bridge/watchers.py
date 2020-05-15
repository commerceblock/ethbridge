#!/usr/bin/env python3
from web3 import Web3, HTTPProvider
import json
import sys
import logging
from time import sleep, time
from hashlib import sha256 as _sha256
from .daemon import DaemonThread
from .test_framework.authproxy import JSONRPCException
from .connectivity import getoceand

INTERVAL_DEFAULT = 60

def round_time(period, time):
    time_mod = time % period
    if time_mod == 0:
        return time
    if time_mod >= period / 2:
        return time - time_mod + period
    return time - time_mod

class OceanWatcher(DaemonThread):
    def __init__(self, conf, signer=None):
        super().__init__()
        self.conf = conf
        self.ocean = getoceand(self.conf)
        self.default_interval = INTERVAL_DEFAULT if "interval" not in conf else conf["interval"]
        self.interval = self.default_interval
        self.logger = logging.getLogger(self.__class__.__name__)

        self.signer = signer
        self.ocean = OceanWallet(conf)
        self.eth = EthWallet(conf)

    def set_init_block_time(self):
        if self.init_block_time == 0:
            block_hash = self.get_blockhash(1)
            if block_hash == None:
                return False
            block_header = self.get_blockheader(block_hash)
            if block_header == None or 'time' not in block_header:
                return False
            self.init_block_time = round_time(self.default_interval, block_header['time'])
        return True

    def run(self):
        while not self.stopped():
            sleep(self.interval - time() % self.interval)
            start_time = int(time())

            #get all addresses and amounts of all transactions recieved to the deposit address
            recieved_txs = self.ocean.get_deposit_txs(conf)
            #check to see if any have not already been minted
            new_txs = self.eth.check_deposits(conf, recieved_txs)
            for tx in new_txs:
                self.logger.info("New Ocean deposit: "+tx["txid"]+" Sending address: "+tx["address"]+" Amount: "+str(tx["amount"]))
            #for each verified new deposit transaction, mint the contract tokens on Ethereum to the sending address
            mint_txs = self.eth.mint_tokens(conf, new_txs)

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
        self.w3 = Web3(Web3.HTTPProvider(conf["id"]))
        self.default_interval = INTERVAL_DEFAULT if "interval" not in conf else conf["interval"]
        self.interval = self.default_interval
        self.my_id = conf["id"] 
        self.logger = logging.getLogger(self.__class__.__name__)

        self.signer = signer
        self.ocean = OceanWallet(conf)
        self.eth = EthWallet(conf)

    def set_init_block_time(self):
        if self.init_block_time == 0:
            block_hash = self.get_blockhash(1)
            if block_hash == None:
                return False
            block_header = self.get_blockheader(block_hash)
            if block_header == None or 'time' not in block_header:
                return False
            self.init_block_time = round_time(self.default_interval, block_header['time'])
        return True

    def run(self):
        while not self.stopped():
            sleep(self.interval - time() % self.interval)
            start_time = int(time())

            #get all addresses and amounts of all transactions recieved to the deposit address
            recieved_txs = self.ocean.get_deposit_txs(conf)
            #check to see if any have not already been minted
            new_txs = self.eth.check_deposits(conf, recieved_txs)
            for tx in new_txs:
                self.logger.info("New Ocean deposit: "+tx["txid"]+" Sending address: "+tx["address"]+" Amount: "+str(tx["amount"]))
            #for each verified new deposit transaction, mint the contract tokens on Ethereum to the sending address
            mint_txs = self.eth.mint_tokens(conf, new_txs)

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


def sha256(x):
    return _sha256(x).digest()

def double_sha256(x):
    return sha256(sha256(x))
