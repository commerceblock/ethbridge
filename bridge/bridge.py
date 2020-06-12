#!/usr/bin/env python3
import os
import random
import sys
import shutil
import logging
import json
import time
import argparse
from decimal import *
from pdb import set_trace
from .watchers import OceanWatcher
from .watchers import EthWatcher
from .hsm import HsmPkcs11
from .connectivity import getoceand, loadConfig

PRVKEY = ""

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rpcconnect', required=True, type=str, help="Client RPC host")
    parser.add_argument('--rpcport', required=True, type=str, help="Client RPC port")
    parser.add_argument('--rpcuser', required=True, type=str, help="RPC username for client")
    parser.add_argument('--rpcpassword', required=True, type=str, help="RPC password for client")
    parser.add_argument('--id', required=True, type=str, help="Infura web3 endpoint")
    
    parser.add_argument('--contract',required=True, type=str, help="Contract address for Ethereum issuance")
    parser.add_argument('--ethkey', required=True, type=str, help="Private key for Ethereum issuance")
    parser.add_argument('--ethaddress', required=True, type=str, help="Address for Ethereum issuance")

    parser.add_argument('--oceankey', default=PRVKEY, type=str, help="Private key for ocean bridge address")
    parser.add_argument('--oceanaddress', type=str, help="Ocean bridge deposit address")
    parser.add_argument('--hsm', default=False, type=bool, help="Specify if an HSM will be used for signing signing transactions")
    parser.add_argument('--whitelist', default=0, type=int, help="Whitelist policy: 0. None. 1. Save tx if not whitelisted. 2. Return Eth tokens to address if not whitelisted.")
    parser.add_argument('--interval', default=60, type=int, help="The frequency at which the daemon checks for new transactions.")
    return parser.parse_args()

def main():
    args = parse_args()

    logging.basicConfig(
        format='%(asctime)s %(name)s:%(levelname)s:%(process)d: %(message)s',
        level=logging.INFO
    )

    conf = {}
    conf["interval"] = args.interval
    conf["rpcuser"] = args.rpcuser
    conf["rpcpassword"] = args.rpcpassword
    conf["rpcport"] = args.rpcport
    conf["rpcconnect"] = args.rpcconnect
    conf["id"] = args.id

    ocnk = args.oceankey
    conf["oceankey"] = ocnk
    conf["oceanaddress"] = args.oceanaddress
    conf["ethkey"] = args.ethkey
    conf["ethaddress"] = args.ethaddress
    conf["contract"] = args.contract

    signer = None
    if args.hsm:
        signer = HsmPkcs11(os.environ['KEY_LABEL'])

    ocean_watch = OceanWatcher(conf, signer)
    ocean_watch.start()

    eth_watch = EthWatcher(conf, signer)
    eth_watch.start()

    try:
        while 1:
            if ocean_watch.stopped():
                ocean_watch.join()
                raise Exception("Node thread has stopped")
            if eth_watch.stopped():
                eth_watch.join()
                raise Exception("Node thread has stopped")
            time.sleep(0.01)
    except KeyboardInterrupt:
        ocean_watch.stop()
        ocean_watch.join()
        eth_watch.stop()
        eth_watch.join()


if __name__ == "__main__":
    main()
