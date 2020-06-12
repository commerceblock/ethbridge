#!/usr/bin/env python3
import logging
import sys
from .test_framework.authproxy import JSONRPCException
from .connectivity import getoceand
import bisect
import collections
from .utils import pub_to_dgld_address

class OceanWallet():
    #An ocean address together with a pubkey and pegin nonce
    Address = collections.namedtuple('Address', 'address pubkey nonce')
    #Represents a transfer of wrapped_DGLD
    Transfer = collections.namedtuple('Transfer', 'from_ to amount transactionHash')

    #Overrides the > and < comparison operators to sort by numeric value of blockindex
    #If block indices are equal, sorts by txid
    #Note that txid is stored as a string, so the comparison is lexicographic by ASCII value
    class sorted_tx(dict):
      def __gt__(self, other):
          inThis = int(self['blocktime'])
          inThat = int(other['blocktime'])
          if inThis == inThat:
              return self['txid'] > other['txid']
          return inThis > inThat

      def __lt__(self, other):
          inThis = int(self['blocktime'])
          inThat = int(other['blocktime'])
          if inThis == inThat:
              return self['txid'] < other['txid']
          return inThis < inThat

      def __hash__(self):
        return hash(self.__key())

      def __key(self):
        return tuple(sorted(self.items()))

    #A key counter beginning at 1
    class key_counter(dict):
        def increment(self, key):
            if key in self:
                self[key] = self[key] + 1
            else:
                self[key] = 1
            return self[key]
    
    def __init__(self, conf):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.ocean = getoceand(conf)
        self.key = conf["oceankey"]
        self.address = conf["oceanaddress"]
        #A map of deposit 'from' address to nonce
        #Nonce begins at 1 and is incremented by 1 for each new deposit transaction from the same address
        self.deposit_address_nonce = self.key_counter()
        #Check if the node wallet already has the deposit key before importing
        validate = self.ocean.validateaddress(self.address)
        print(validate)
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

        #The number of transactions associated with the wallet
        self.tx_count=0
        #A list of transactions sent from this wallet
        self.sent=[]
        self.update_sent()

            
    def get_deposit_txs(self):
        deposit_txs = []
        #print("get_deposit_txs")
        try:
            unspent = self.ocean.listunspent()
            for raddress in unspent:
                if raddress["address"] == self.address:
                    #print("**** raddress: {}".format(raddress))
                    #print("**** address: {}".format(raddress["address"]))
                    #print("**** self.address: {}".format(self.address))
                    tx=raddress["txid"]
                    #print("***** get_deposit_txs tx: {}".format(tx))
                    txin=self.ocean.getrawtransaction(tx,1)
                    txin["amount"]=self.ocean.gettransaction(tx)["amount"]
                    print("***** get_deposit_txs amount: {}".format(txin["amount"]))
                    txin = self.sorted_tx(txin)
                    #print("***** get_deposit_txs: txin: {}".format(txin))
                    #Insert the transactions by sorted_tx order
                    bisect.insort_left(deposit_txs, txin)
            #print("***** get_deposit_txs: len(deposit_txs): {}".format(len(deposit_txs)))
            return deposit_txs
        except Exception as e:
            self.logger.warning("failed to get ocean deposit transactions: {}".format(str(e)))
            return None

    def get_sending_address(self, new_txs):
        #print("******************* get sending address *********************")
        new_txs_with_address = []
        #Only p2pkh addresses can be wrapped
        new_unbridgable_txs = []
        #get the sending address
        #if there are more than 1 input, we take the first address
        #if the other input addresses are different, we print a log/warning
        counter=0
        try:
            for tx in new_txs:
                #print("get_sending_address: tx: {}".format(tx))
                addresses = []
                #print("len(tx[\"vin\"]): {}".format(len(tx["vin"])))
                for inputs in tx["vin"]:
                    #print("************** get_sending: inputs: {}".format(inputs))
                    txin = self.ocean.getrawtransaction(inputs["txid"],1)
                    #print("**** txin")
                    #print("len(txin[\"vout\"]): {}".format(len(txin["vout"])))
                    for vout in txin["vout"]:
                        out=dict(txin["vout"][inputs["vout"]])
                        #print("***** out: {}".format(out))
                        if out['scriptPubKey']['type'] == 'pubkeyhash':
                            #print("****inputs: {}".format(inputs))
                            in_pubkey=inputs["scriptSig"]["hex"][-66:]
                            #print("in_pubkey: {}".format(in_pubkey))
                            in_address=pub_to_dgld_address(bytes.fromhex(in_pubkey))
                            #print("in_address: {}".format(in_address))
                        else:
                            in_pubkey="unknown"
                            in_address="unknown"
                            #Address, pubkey, pegin nonce
                        #print("**** appending address")
                        addresses.append(self.Address(address=in_address, pubkey=in_pubkey, nonce=-1))
                        counter=counter+1
                #print("**** addresses: {}".format(addresses))
                #print("**** setting sending address")
                address=addresses[0]
                if len(addresses) != 1:
                    self.logger.warning("More than one address as input to txid: {}. Addresses: {}".format(tx["txid"], addresses))
                #Can only peg in if the send address' pub key is known.
                #print("******* incrementing nonce")
                #print("******address.address: {}".format(address.address))
                nonce=self.deposit_address_nonce.increment(address.address)
                tx['sendingaddress']=self.Address(address=address.address, pubkey=address.pubkey, nonce=nonce)
                #print("**** appending txs")
                new_txs_with_address.append(tx)
            #print("new_txs_with_address: {}".format(new_txs_with_address))
            return new_txs_with_address
        except Exception as e:
            self.logger.warning("failed get sending address ocean: {}".format(e))
            return None

    def update_sent(self):
        try:
            #Get transactions 100 at a time
            while True:
                transactions = self.ocean.listtransactions('*', 100, self.tx_count, False)
                if len(transactions) == 0:
                    break
                for tx in transactions:
                    if tx['address'] == self.address and tx['category'] == 'send':
                        bisection.insort_left(self.sent, self.sorted_tx(tx))
                self.tx_count+=len(transactions)
        except Exception as e:
            self.logger.warning("failed to get ocean deposit transactions: {}".format(e))
            return None        
        
    def is_already_sent(self, tx: Transfer):
        for item in self.sent:
            if(tx['to']['nonce'] == item['to']['nonce']):
                return True
        return False
        
    def check_deposits(self, conf, new_txs: [Transfer]):
        #check that the new transactions recieved have not been previously paid out from the Ocean deposit wallet
        self.update_sent()
        filtered_list=list(set(filter(lambda x: not self.is_already_sent(x), new_txs)))
        return filtered_list

    def send_tokens(self, payment_list):
        non_whitelisted = []
        try:
            for payment in payment_list:
                is_whitelisted = self.querywhitelist(payment["address"])
                if is_whitelisted:
                    txid = self.ocean.sendanytoaddress(payment["address"],payment["amount"])
                else:
                    self.logger.warning("Ocean payment: "+payment["address"]+" from Eth TxID "+payment["txid"]+" not whitelisted")
                    non_whitelisted.append(payment)
        except Exception as e:
            self.logger.warning("failed ocean payment tx generation: {}".format(e))
            return None
        return non_whitelisted








      
