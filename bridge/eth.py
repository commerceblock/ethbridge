#!/usr/bin/env python3A
from web3 import Web3, HTTPProvider
from web3.middleware import local_filter_middleware
import logging
import sys
from .test_framework.authproxy import JSONRPCException
from eth_account import Account
import collections
from .utils import pub_to_eth_address
import json


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
    #An ethereum address together with a pubkey and pegin nonce
    Address = collections.namedtuple('Address', 'address pubkey nonce')
    #Represents a transfer of wrapped_DGLD
    Transfer = collections.namedtuple('Transfer', 'from_ to amount transactionHash')
    
    def __init__(self, conf):
        self.w3 = Web3(Web3.HTTPProvider(conf["id"]))
        if not self.w3.isConnected():
            raise EthWalletError('web3 failed to connect')
        self.w3.middleware_onion.add(local_filter_middleware)
        self.logger = logging.getLogger(self.__class__.__name__)
        with open('contract/wrapped_DGLD.json') as json_file:
            abi=json.loads(json_file.read())['abi']
        self.account=Account.from_key(conf['ethkey'])
        self.contract=self.w3.eth.contract(address=conf['contract'],abi=abi)
        #Get the pegout address
        self.pegout_address=self.contract.functions.pegoutAddress
        print('pegout address: {}'.format(self.pegout_address))
        #A filter for the ethereum log for pegout events
        filter_builder=self.contract.events.Transfer().build_filter()
        filter_builder.fromBlock=0
        filter_builder.argument_filters={'to': self.pegout_address}
        self.pegout_filter=filter_builder.deploy(self.w3)
        #Mint events are transfers from the zero address
        filter_builder=self.contract.events.Transfer.build_filter()
        filter_builder.fromBlock=0
        filter_builder.argument_filters={'from': "0x0000000000000000000000000000000000000000"}
        self.mint_filter = filter_builder.deploy(self.w3)
        self.init_minted()
        print(self.minted)

    #Get a list of previously minted pegin transactions
    def init_minted(self):
        self.minted=set()
        self.update_minted_from_events(self.mint_filter.get_all_entries())
                                            
    def update_minted(self):
        self.update_minted_from_events(self.mint_filter.get_new_entries())
                                            
    def update_minted_from_events(self, events):
        for mint_event in events:
            pegin=Transfer(to=Address(address=mint_event['to']), amount=mint_event['amount'], transactionHash=mint_event['transactionHash']);
            pegin_filter=self.contract.events.Pegin(fromBlock="0x0", argument_filters={'transactionHash': pegin['transactionHash']})
            pegin_events=pegin_filter.get_all_events()
            if len(pegin_events) != 1:
                raise EthWalletError('there should only be one pegin event per pegin transaction')
            pegin['to']['nonce']=pegin_events[0]['nonce']
            self.minted.add(pegin)

    def get_burn_txs(self):
        pegout_txs = []
        #get all transactions on ethereum that have been sent to the burn address (to peg back into Ocean)
        try:
            for event in  self.pegout_filter.get_new_entries():
                pegout_txs.add(Transfer(from_=Address(address=event['from']),
                                            amount=event['amount'],
                                            transactionHash=event['transactionHash']))
            return pegout_txs
        except Exception as e:
            self.logger.warning("failed get eth burn transactions: {}".format(e))
            return None

    def is_already_minted(self, tx: Transfer):
        for item in self.minted:
          if(tx['to']['address'] == item['to']['address'] and tx['to']['nonce'] == item['to']['nonce']) :
              return True
        return False
                                            
    def check_deposits(self, new_txs: [Transfer]):
        #filter the transactions to previously unminted ones
        self.update_minted()
        filtered_list=list(set(filter(lambda x: not self.is_already_minted(x), new_txs)))
        return filtered_list

    def mint_tokens(self, payment_list: [Transfer]):
        minted_txs = []
        previously_minted_txs = []
        txnonce=self.w3.eth.getTransactionCount(self.address)
        try:
            for payment in payment_list:
                #mint the required tokens
                to = eth_pub_to_address(codecs.encode(bytes.fromhex(payment['to']['pubkey']),'hex'))
                nonce = payment['to']['nonce']
                gas_estimate=self.contract.functions.pegin(to, payment['amount'], nonce)
                if gas_estimate > self.txn_gas_limit:
                    raise Exception('gas limit exceeded: ' + str(gas_estimate) + ' > ' + str(self.txn_gas_limit))
                txn = self.contract.functions.pegin(to, payment['amount'], nonce)\
                    .buildTransaction({
                        'chainId': 3,
                        'gas': gas_estimate,
                        'nonce': txnonce
                        })
                signed_txn = self.account.sign_transaction(txn)
                print(signed_txn)
                self.w3.eth.sendRawTransaction(signed_txn.rawTransaction)
                txnonce=txnonce+1
                minted_txs.add(signed_txn)
            return minted_txs
        except Exception as e:
            self.logger.warning("failed ocean payment tx generation: {}".format(e))
            return None




                                            


      
