#!/usr/bin/env python3
import logging
import sys
from .test_framework.authproxy import JSONRPCException
from .connectivity import getoceand
import bisect
import collections
from .utils import pub_to_dgld_address, PegID, Transfer


class OceanWallet():
    class HDKeyIDError(Exception):
        def __init__(self, expected, found):
            self.expected=expected
            self.found=found

        def __str__(self):
            return "OceanWallet HD Key ID Error: expected {}, found {}".format(self.expected, self.found)

    
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
        self.logger.info("Getting ocean wallet info...")
        hdkey=self.ocean.getwalletinfo()["hdmasterkeyid"]
        if hdkey != conf["oceanhdmasterkeyid"]:
            err = self.HDKeyIDError(conf["oceanhdmasterkeyid"], hdkey)
            self.logger.error("{}".format(err))
            raise err
        self.key = conf["oceankey"]
        self.changekey = conf["oceanchangekey"]
        self.address = conf["oceanaddress"]
        self.changeaddress = conf["oceanchangeaddress"]
        self.decimals = conf["decimals"]
        self.min_confirmations = conf["mindgldconfirmations"]
        self.max_confirmations = conf["maxdgldconfirmations"]
        self.fee = conf["dgldfixedfee"]
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
            self.logger.info("Importing priv key...")
            try:
                self.ocean.importprivkey(self.key,"privkey",rescan_needed)
            except Exception as e:
                self.logger.error("{}\nFailed to import Ocean wallet private key".format(e))
                sys.exit(1)

            try:
                self.ocean.importprivkey(self.changekey,"privkey",rescan_needed)
            except Exception as e:
                self.logger.error("{}\nFailed to import Ocean wallet change private key".format(e))
                sys.exit(1)

            #Have just imported the private key so another rescan should be unnecesasary
            rescan_needed=False

        #Check if we still need to import the address given that we have just imported the private key
        self.logger.info("Ocean validating address...")
        validate = self.ocean.validateaddress(self.address)
        have_va_addr = bool(validate["ismine"])
        if have_va_addr == False:
            ocean.importaddress(self.p2sh,"deposit",rescan_needed)
            validate = ocean.validateaddress(self.addresses)

        #A list of transactions sent from this wallet
        self.sent=set()
        self.update_sent()
        self.pubkey_map={}
    def get_deposit_txs(self):
        deposit_txs = []
        try:
            received = self.ocean.listreceivedbyaddress(self.min_confirmations, True, True)
            for raddress in received:
                if raddress["address"] == self.address:
                    for tx in raddress["txids"]:
                        txin=self.ocean.getrawtransaction(tx,1)
                        #Ignore older deposit txs - assume they have already been pegged
                        if txin["confirmations"] > self.max_confirmations:
                            continue
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
                addresses = set()
                metadata = []
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
                        addresses.add(in_address)
                        counter=counter+1
                address=list(addresses)[0]
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
        tx_skip=0
        try:
            #Get transactions 100 at a time
            while True:
                transactions = self.ocean.listtransactions('*', 100, tx_skip, True)
                if len(transactions) == 0:
                    break
                for tx in transactions:
                    if tx['category'] == 'send':
                        txid=tx['txid']
                        #If the transaction is not in the blockchain or mempool we need to check for in-wallet transactions as well.
                        try:
                            rawtx = self.ocean.getrawtransaction(tx["txid"])
                        except:
                            #These are wallet transactions so we use gettransaction followed by decoderawtransaction
                            rawtx=self.ocean.gettransaction(txid)['hex']
                        decoded=self.ocean.decoderawtransaction(rawtx)
                        for out in decoded['vout']:
                            if out['scriptPubKey']['type'] == 'nulldata' and \
                               out['scriptPubKey']['hex'][:4] == '6a20' :
                                data='0x'+out['scriptPubKey']['hex'][4:]
                                if data not in self.sent:
                                    self.sent.add(data)
                tx_skip = tx_skip + len(transactions)
        except Exception as e:
            self.logger.warning("failed to update sent transactions: {}".format(e))
            return None        

    def get_recipient_address(self, rawtx):
        for out in rawtx['vout']:
            if addresses in out:
                return out['addresses'][0]
        
        
    def is_already_sent(self, tx: Transfer):
        if tx.transactionHash in self.sent:
            if tx.transactionHash in self.pending_pegouts:
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
                #The ethereum transaction hash
                txhash=payment.transactionHash
                if is_whitelisted:
                    #include metadata in the tx.
                    if txhash in self.pending_pegouts:
                        self.logger.warning("Pegout ID: {} already pending".format(txhash))
                        continue
                    amount=payment.amount
                    #Convert the amount to DGLD and subtract a transaction fee from the amount
                    amount=amount/(10 ** self.decimals) - self.fee
                    txhash_fmt=self.format_hex_str(txhash)
                    txid=None
                    txid = self.ocean.sendanytoaddress(payment.to, amount, "","", True, False, 1, txhash_fmt, self.changeaddress)
#                    txid = self.ocean.createanytoaddress(payment.to, amount, True, False, 1, False, txhash_fmt)[0]
#                    txid = self.ocean.signrawtransaction(txid)
#                    print("signed tx: {}".format(txid))
                    
                    self.pending_pegouts.add(txhash)
                    self.logger.info("Ocean payment: sending tokens to ocean address: {}, amount: {}, nonce: {}, ocean txid: {}".format(payment.to, amount, txhash, txid))
                else:
                    self.logger.warning("Ocean payment: "+payment.to+" from Eth TxID "+txhash+" not whitelisted")
                    non_whitelisted.append(payment)
        except Exception as e:
            self.logger.warning("failed ocean payment tx generation: {}".format(e))
            return None
        return non_whitelisted








      
