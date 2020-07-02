#!/usr/bin/env python3
from web3 import Web3, HTTPProvider, WebsocketProvider
import logging
import sys
from .test_framework.authproxy import JSONRPCException
from eth_account import Account
import collections
from .utils import pub_bytes_to_eth_address
import json
from time import sleep, time
import ssl
import pathlib
from .utils import PegID, Transfer, pub_bytes_to_eth_address, pub_to_dgld_address, compress


class EthWalletError(Exception):
    def __init__(self, *args):
        if args:
            self.message = args[0]
        else:
            self.message = None

    def __str__(self):
        if self.message:
            return 'EthWalletError, {} '.format(self.message)
        else:
            return 'EthWalletError'
        
class EthWallet():
    #An ethereum address together with a pegin nonce
    #Address = collections.namedtuple('Address', 'address nonce')
    #Represents a transfer of wrapped_DGLD
    #Transfer = collections.namedtuple('Transfer', 'from_ to amount transactionHash')
    
    def __init__(self, conf):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.fromBlock=conf["ethfromblock"]
        self.synced_to_block=self.fromBlock       
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        certstore = pathlib.Path(conf["certstore"])
        self.ssl_context.load_verify_locations(certstore)
        self.logger.info("Initializing websocket provider...")
        self.provider=Web3.WebsocketProvider(conf["id"],websocket_kwargs={'ssl': self.ssl_context, 'timeout': 999999999}, websocket_timeout=conf["ethwstimeout"])
        self.logger.info("Initializing web3...")
        self.w3 = Web3(self.provider)
        if not self.w3.isConnected():
            raise EthWalletError('web3 failed to connect')
        self.gaspricelimit=self.w3.toWei(conf["gaspricelimit"], 'Gwei')
        with open('contract/wrapped_DGLD.json') as json_file:
            abi=json.loads(json_file.read())['abi']
        self.logger.info("Initializing eth account...")
        self.account=Account.from_key(conf['ethkey'])
        self.w3.defaultAccount=self.account
        self.key=conf['ethkey']
        assert(self.account.address == conf['ethaddress'])
        self.logger.info("Initializing contract...")
        self.contract=self.w3.eth.contract(address=conf['contract'],abi=abi)
        #Get the pegout address
        self.logger.info("Getting pegout address...")
        self.pegout_address=self.contract.functions.pegoutAddress().call()
        self.minconfirmations=conf['minethconfirmations']
        #The block up to which pegouts have been processed
        self.pegin_gas_estimate=100000
        #Subscribe to events
        self.logger.info("Initializing event logs...")
        self.init_minted()
        self.init_pegout_txs()

    #Get the blocknumber that satisfies the minimum number of confirmations
    def get_max_blocknumber(self):
        return self.w3.eth.blockNumber-self.minconfirmations

    #A new filter must be redeployed each time they are used as persistency is not guaranteed
    def get_mint_filter(self, fromBlock=None):
        if fromBlock == None:
            fromBlock=self.fromBlock
        #Mint events are transfers from the zero address
        filter_builder=self.contract.events.Transfer.build_filter()
        filter_builder.fromBlock=fromBlock
        filter_builder.args['from'].match_any("0x0000000000000000000000000000000000000000")
        return filter_builder.deploy(self.w3)

    def get_pegin_filter(self, fromBlock=None):
        if fromBlock == None:
            fromBlock=self.fromBlock
        #Pegin events
        filter_builder=self.contract.events.Pegin.build_filter()
        filter_builder.fromBlock=fromBlock
        return filter_builder.deploy(self.w3)

    def get_pegout_filter(self, fromBlock=None):
        if fromBlock == None:
            fromBlock=self.fromBlock
        #A filter for the ethereum log for pegout events
        filter_builder=self.contract.events.Transfer.build_filter()
        filter_builder.fromBlock=fromBlock
        filter_builder.args.to.match_any(self.pegout_address)
        return filter_builder.deploy(self.w3)

    def init_minted(self):
        self.minted={}
        self.update_minted(self.fromBlock)

    def update_minted(self, fromBlock=None):
        self.logger.info("Eth updating minted...")
        if fromBlock == None:
            fromBlock=self.synced_to_block + 1
        self.logger.info("Getting filters. fromBlock = {}".format(fromBlock))
        mint_filter=self.get_mint_filter(fromBlock)
        pegin_filter=self.get_pegin_filter(fromBlock)
        self.logger.info("Getting all mint_filter entries".format(fromBlock))
        entries=mint_filter.get_all_entries()
        self.logger.info("Getting all pegin_filter entries".format(fromBlock))
        pegin_entries=pegin_filter.get_all_entries()

        if entries:
            self.logger.info("Entries found, updating minted from events".format(fromBlock))
            self.update_minted_from_events(entries, pegin_entries)

        self.logger.info("...eth finished updating minted.")
        
    def update_minted_from_events(self, events, pegin_events):
        nonce_dict={}
        for event in pegin_events:
            nonce_dict[event['transactionHash'].hex()]=event['args']['id']

        for event in events:
            transactionHash=event['transactionHash'].hex()
            if not transactionHash in nonce_dict:
                self.logger.warning("failed get pegin nonce for transaction: {}".format(transactionHash))
                continue
            self.minted[PegID(address=event['args']['to'],
                                        nonce=nonce_dict[transactionHash])] = transactionHash

    def get_ocean_destination_from_burn_event(self, event):
        tx = self.w3.eth.getTransaction(event['transactionHash'])
        return pub_to_dgld_address(compress(int.from_bytes(tx['publicKey'][:32], byteorder='big'), int.from_bytes(tx['publicKey'][32:], byteorder='big')))

    def init_pegout_txs(self):
        self.pegout_txs=[]
        self.update_pegout_txs(self.fromBlock)

    def update_pegout_txs(self, fromBlock=None):
        self.logger.info("Update pegout txs...")
        if fromBlock == None:
            fromBlock=self.synced_to_block + 1
        try:
            self.logger.info("Getting pegout filter. fromBlock = {}".format(fromBlock))
            pegout_filter=self.get_pegout_filter(fromBlock)
            self.logger.info("Getting all pegout filter entries.")
            events = pegout_filter.get_all_entries()
            synced_to_block=self.synced_to_block
            self.logger.info("Getting max block number.")
            maxblock = self.get_max_blocknumber()

            self.logger.info("Processing events.")
            for event in events:
                #Set the 'to' address to the ocean dgld address
                #This enforces the minimum number of confirmations
                if event['blockNumber'] > maxblock:
                    continue
                synced_to_block = max([event['blockNumber'],synced_to_block])
                to=self.get_ocean_destination_from_burn_event(event)
                self.pegout_txs.append(Transfer(from_=event['args']['from'],
                                                to=to,
                                                amount=event['args']['value'],
                                                transactionHash=event['transactionHash'].hex()))
        except Exception as e:
            self.logger.warning("failed get eth burn transactions: {}".format(e))
            return None

        self.logger.info("... finished update pegout txs.")
        self.synced_to_block=synced_to_block
        
    #get the latest transactions on ethereum that have been sent to the burn address (to peg back into Ocean)
    def get_burn_txs(self):
        self.update_pegout_txs()
        pegout_txs=self.pegout_txs
        self.pegout_txs=[]
        return pegout_txs
        
    def is_already_minted(self, tx: Transfer):
        ocean_eth_address=pub_bytes_to_eth_address(bytes.fromhex(tx['pegpubkey']))
        ocean_nonce=tx['sendingaddress'][1]
        pegid=PegID(address=ocean_eth_address, nonce=ocean_nonce)
        if pegid in self.minted:
            return True
        return False
                                            
    def check_deposits(self, new_txs: [Transfer]):
        if not new_txs:
            return
        #filter the transactions to previously unminted ones
        self.update_minted()
        filtered_list=[]
        for tx in new_txs:
            if not self.is_already_minted(tx):
                filtered_list.append(tx)
#        filtered_list=list(set(filter(lambda x: not self.is_already_minted(x), new_txs)))
        return filtered_list

    def mint_tokens(self, payment_list: [Transfer]):
        minted_txs = []
        previously_minted_txs = []
        try:
            for payment in payment_list:
                txnonce=self.w3.eth.getTransactionCount(Web3.toChecksumAddress(self.account.address))
                #mint the required tokens
                to = pub_bytes_to_eth_address(bytes.fromhex(payment['pegpubkey']))
                nonce = payment['sendingaddress'].nonce
                amount=payment['pegamount']                     
                pegin_function=self.contract.functions.pegin(to, amount, nonce)
                gasPrice=long(self.w3.eth.gasPrice*1.1)
                
                if gasPrice > self.gaspricelimit:
                    self.logger.warning("limiting gas price from {} to {} wei".format(gasPrice, self.gaspricelimit))
                    gasPrice = self.gaspricelimit

                raw_balance = self.contract.functions.balanceOf(self.account.address).call()
                balance = raw_balance // 100000000
                gas_estimate=self.pegin_gas_estimate

                txn = pegin_function.buildTransaction({'nonce': txnonce,
                                                       'from': self.account.address,
                                                       'gas': gas_estimate,
                                                       'gasPrice': gasPrice
                })
                signed_txn = self.account.sign_transaction(txn)
                txn_hash=self.w3.eth.sendRawTransaction(signed_txn.rawTransaction)
                txn_receipt = self.w3.eth.waitForTransactionReceipt(txn_hash)
                minted_txs.append((payment, txn_receipt))
            return minted_txs
        except Exception as e:
            self.logger.warning("failed ocean payment tx generation: {}".format(e))
            return None




                                            


      
