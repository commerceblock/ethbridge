#!/usr/bin/env python3
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
        self.my_id = conf["id"] 
        self.logger = logging.getLogger(self.__class__.__name__)

        self.signer = signer

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
            step = int(time()) % (self.interval) / self.interval

            height = self.get_blockcount()
            if height == None:
                continue
            elif height > 0 and not self.set_init_block_time():
                self.logger.error("could not set init block time")
                continue

    def rpc_retry(self, rpc_func, *args):
        for i in range(5):
            try:
                return rpc_func(*args)
            except Exception as e:
                self.logger.warning("{}\nReconnecting to client...".format(e))
                self.ocean = getoceand(self.conf)
        self.logger.error("Failed reconnecting to client")
        self.stop()

    def get_blockcount(self):
        return self.rpc_retry(self.ocean.getblockcount)

    def get_newblockhex(self):
        return self.rpc_retry(self.ocean.getnewblockhex)

    def get_blockhash(self, height):
        return self.rpc_retry(self.ocean.getblockhash, height)

    def get_blockheader(self, hash):
        return self.rpc_retry(self.ocean.getblockheader, hash)

OCEAN_BASE_HEADER_SIZE = 172

def header_hash(block):
    challenge_size = block[OCEAN_BASE_HEADER_SIZE]
    header_without_proof = block[:OCEAN_BASE_HEADER_SIZE+1+challenge_size]
    return double_sha256(header_without_proof)

def get_header(block):
    challenge_size = block[OCEAN_BASE_HEADER_SIZE]
    proof_size = block[OCEAN_BASE_HEADER_SIZE+1+challenge_size]
    return block[:OCEAN_BASE_HEADER_SIZE+1+challenge_size+1+proof_size]

def sha256(x):
    return _sha256(x).digest()

def double_sha256(x):
    return sha256(sha256(x))
