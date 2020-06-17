#!/usr/bin/env python3
import logging
import sys
from .test_framework.authproxy import JSONRPCException
from .connectivity import getoceand
import bisect
import collections
from .utils import pub_to_dgld_address, PegID, Transfer


class OceanWallet():
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
        self.decimals = 8
        self.min_confirmations = 1
        self.max_confirmations = 9999999
        #A map of deposit 'from' address to nonce
        #Nonce begins at 1 and is incremented by 1 for each new deposit transaction from the same address
        self.deposit_address_nonce = self.key_counter()
        #Check if the node wallet already has the deposit key before importing
        validate = self.ocean.validateaddress(self.address)
        have_va_addr = bool(validate["ismine"])
        watch_only = bool(validate["iswatchonly"])
        have_va_prvkey = have_va_addr and not watch_only
        rescan_needed = True
        self.received_txids = set()
        self.pending_pegouts = set()
        
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
        self.tx_skip=0
        #A list of transactions sent from this wallet
        self.sent=[]
        self.update_sent()
        self.pubkey_map={}

    def get_deposit_txs(self):
        deposit_txs = []
        try:
            unspent = self.ocean.listunspent()
            for raddress in unspent:
                if raddress["address"] == self.address:
                    tx=raddress["txid"]
                    txin=self.ocean.getrawtransaction(tx,1)
                    txin = self.sorted_tx(txin)
                    #Insert the transactions by sorted_tx order
                    pegamount=0
                    for out in txin['vout']:
                        spk=out['scriptPubKey']
                        if spk['type'] == 'pubkeyhash' and spk['addresses'][0] == self.address:
                            pegamount = pegamount + out['value']

                    txin['pegamount']=int(pegamount * 10**self.decimals)
                    
                    bisect.insort_left(deposit_txs, txin)
            return deposit_txs
        except Exception as e:
            self.logger.warning("failed to get ocean deposit transactions: {}".format(str(e)))
            return None

    def get_sending_address(self, new_txs):
        new_txs_with_address = []
        #Only p2pkh addresses can be wrapped
        new_unbridgable_txs = []
        #get the sending address
        #if there are more than 1 input, we take the first address
        #if the other input addresses are different, we print a log/warning
        counter=0
        try:
            for tx in new_txs:
                addresses = []
                for inputs in tx["vin"]:
                    txin = self.ocean.getrawtransaction(inputs["txid"],1)
                    for vout in txin["vout"]:
                        out=dict(txin["vout"][inputs["vout"]])
                        if out['scriptPubKey']['type'] == 'pubkeyhash':
                            in_pubkey=inputs["scriptSig"]["hex"][-66:]
                            in_address=pub_to_dgld_address(bytes.fromhex(in_pubkey))
                        else:
                            in_pubkey="unknown"
                            in_address="unknown"
                            #Address, pubkey, pegin nonce
                        self.pubkey_map[in_address]=in_pubkey
                        addresses.append(in_address)
                        counter=counter+1
                address=addresses[0]
                if len(addresses) != 1:
                    self.logger.warning("More than one address as input to txid: {}. Addresses: {}".format(tx["txid"], addresses))
                #Can only peg in if the send address' pub key is known.
                txid=tx['txid']
                if txid in self.received_txids:
                    nonce=self.deposit_address_nonce[address]
                else:
                    nonce=self.deposit_address_nonce.increment(address)
                    self.received_txids.add(txid)
                tx['sendingaddress']=PegID(address=address,  nonce=nonce)
                tx['pegpubkey']=self.pubkey_map[address]
                new_txs_with_address.append(tx)
            return new_txs_with_address
        except Exception as e:
            self.logger.warning("failed get sending address ocean: {}".format(e))
            return None

    def update_sent(self):
        try:
            #Get transactions 100 at a time
            while True:
                transactions = self.ocean.listtransactions('*', 100, self.tx_skip, False)
                if len(transactions) == 0:
                    break
                for tx in transactions:
                    if tx['category'] == 'send' and 'address' in tx and tx['address'] == self.address:
                        txid=tx['txid']
                        rawtx=self.ocean.getrawtransaction(txid, 1)
                        
                        bisect.insort_left(self.sent, self.sorted_tx(tx))
                self.tx_skip+=len(transactions)
        except Exception as e:
            self.logger.warning("failed to get ocean deposit transactions: {}".format(e))
            return None        

    def get_recipient_address(self, rawtx):
        for out in rawtx['vout']:
            if addresses in out:
                return out['addresses'][0]
        
        
    def is_already_sent(self, tx: Transfer):
        if tx.transactionHash in self.sent:
            self.pending_pegouts.remove(tx.transactionHash)
            return True
        return False
        
    def check_deposits(self, new_txs: [Transfer]):
        #check that the new transactions recieved have not been previously paid out from the Ocean deposit wallet
        self.update_sent()
        filtered_list=list(set(filter(lambda x: not self.is_already_sent(x), new_txs)))
        return filtered_list

    def format_hex_str(self, val):
        if val[:2] == "0x":
            return val[2:]
        else:
            return val
    
    def send_tokens(self, payment_list):
        non_whitelisted = []
        try:
            for payment in payment_list:
                is_whitelisted = self.ocean.querywhitelist(payment.to)
                txhash=payment.transactionHash
                if is_whitelisted:
                    #include metadata in the tx.
                    if txhash in self.pending_pegouts:
                        self.logger.warning("Pegout ID: {} already pending".format(txhash))
                        continue
                    amount=payment.amount
                    amount=amount/(10 ** self.decimals)
                    txhash_fmt=self.format_hex_str(txhash)
                    txid=None
                    txid = self.ocean.sendanytoaddress(payment.to, amount, "","", True, False, 1, txhash_fmt)
#                    txid = self.ocean.createanytoaddress(payment.to, amount, True, False, 1, False, txhash_fmt)[0]
                    
                    self.pending_pegouts.add(txhash)
                    self.logger.info("Ocean payment: sending tokens to ocean address: {}, amount: {}, nonce: {}, ocean txid: {}".format(payment.to, amount, txhash, txid))
                else:
                    self.logger.warning("Ocean payment: "+payment.to+" from Eth TxID "+txhash+" not whitelisted")
                    non_whitelisted.append(payment)
        except Exception as e:
            self.logger.warning("failed ocean payment tx generation: {}".format(e))
            return None
        return non_whitelisted








      
