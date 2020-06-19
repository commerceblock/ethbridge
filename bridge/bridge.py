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
from .watchers import Watcher
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
    parser.add_argument('--interval', default=60, type=int, help="The time interval in seconds between checks for new transactions.")
    parser.add_argument('--minethconfirmations', default=6, type=int, help="The minimum number of confirmations required for deposit transactions on the ethereum blockchain.")
    parser.add_argument('--mindgldconfirmations', default=60, type=int, help="The minimum number of confirmations required for deposit transactions on the DGLD blockchain.")
    parser.add_argument('--maxdgldconfirmations', default=100000, type=int, help="Deposit transactions on the DGLD blockchain will be ignored after this number of confirmations.")
    parser.add_argument('--decimals', default=8, type=int, help="The number of decimal places of the token unit.")
    parser.add_argument('--dgldfixedfee', default=0.0005, type=float, help="The fee subtracted in DGLD for transferring from wrapped-DGLD to DGLD")
    return parser.parse_args()

def main():
    args = parse_args()

    logging.basicConfig(
        format='%(asctime)s %(name)s:%(levelname)s:%(process)d: %(message)s',
        level=logging.INFO
    )

    conf = {}
    conf["minethconfirmations"] = args.minethconfirmations
    conf["mindgldconfirmations"] = args.mindgldconfirmations
    conf["maxdgldconfirmations"] = args.maxdgldconfirmations
    conf["decimals"] = args.decimals
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
    conf["dgldfixedfee"] = args.dgldfixedfee

    signer = None
    if args.hsm:
        signer = HsmPkcs11(os.environ['KEY_LABEL'])

    watch = Watcher(conf, signer)
    watch.start()

    try:
        while 1:
            if watch.stopped():
                watch.join()
                raise Exception("Node thread has stopped")
            time.sleep(0.01)
    except KeyboardInterrupt:
        ocean_watch.stop()
        ocean_watch.join()
        eth_watch.stop()
        eth_watch.join()


if __name__ == "__main__":
    main()
