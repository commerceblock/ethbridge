#!/usr/bin/env python3
from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.util import string_to_number, number_to_string
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1
from ecdsa import ecdsa
from ecdsa.keys import VerifyingKey, SigningKey
from ecdsa.curves import SECP256k1
from coincurve import PublicKey
from web3 import Web3
from bitcoin import pubkey_to_address, b58check_to_hex
import codecs
import bitcoin
from eth_account import Account

class MalformedPoint(Exception):
    pass

class InvalidKeyOrAddress(Exception):
    pass

def compress(x: int, y: int) -> bytes:
    e_x = number_to_string(x,SECP256k1.order) #encoded x
    return (b'\x03' + e_x) if y % 2 else (b'\x02' + e_x)


def uncompress(string: bytes, curve=SECP256k1) -> Point:
    if string[:1] not in (b'\x02', b'\x03'):
        raise MalformedPoint("Malformed compressed point encoding")
            
    is_even = string[:1] == b'\x02'
    x = string_to_number(string[1:])
    order = curve.order
    p = curve.curve.p()
    alpha = (pow(x, 3, p) + (curve.curve.a() * x) + curve.curve.b()) % p
    try:
        beta = square_root_mod_prime(alpha, p)
    except SquareRootError as e:
        raise MalformedPoint(
            "Encoding does not correspond to a point on curve", e
        )                                 
    if is_even == bool(beta & 1):
        y = p - beta
    else:
        y = beta
    if not ecdsa.point_is_valid(curve.generator, x, y):
        raise MalformedPoint("Point does not lie on curve")
    return Point(curve.curve, x, y, order)

def eth_address_from_compressed_pubkey_hex(pubkey: str):
    point=uncompress(bytes.fromhex(pubkey))
    pubkey=PublicKey.from_point(point.x(), point.y())
    key_bytes = PublicKey.from_point(point.x(), point.y()).format(compressed=False)
#    print(key_bytes)
    return pub_to_eth_address(codecs.encode(key_bytes,'hex'))

    
def pub_to_dgld_address(pubkey):
    return pubkey_to_address(pubkey, 38)

def dgld_wif_compressed_to_privkey(wif):
#    TgR3YEUGYUzZ5wg4RadMMdFYDrMqxEZL5XxgAKefsBjhXw7ogFvd
#    decoded=b58check_to_hex(wif)
    priv_key_hex=bitcoin.encode_privkey(bitcoin.decode_privkey(wif, 'wif_compressed'), 'hex')
#    print(decoded)
#    decoded=bitcoin.decode_privkey(wif, 'wif')
#    print(decoded)
#    if str(decoded[:2]) != magic_byte:
#        raise InvalidKeyOrAddress("decoded wif begins with {}, should begin with {}".format(str(decoded[:2]), magic_byte))

#    if len(decoded) == 66:
#        if decoded[-2:] != '01':
#            raise InvalidKeyOrAddress("WIF key invalid")
#        else:
#            pass
            #This private key is from a compressed public key. Get the uncompressed private key.
#    return decoded[:64]
                                  #    5ad2518e844c008e26dc09f0e35e0a2414e619b68e504a9f5f7ab07ab7fe981601
    return priv_key_hex


def priv_to_pub(private_key):
    private_key_bytes = codecs.decode_privkey(private_key, 'hex')
#    print("private key: {}, len {}".format(private_key, len(private_key)))
#    print("private key bytes: {}, len {}".format(private_key_bytes, len(private_key_bytes)))
    # Get ECDSA public key
    key = SigningKey.from_string(private_key_bytes, curve=SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
#    print("pub key hex: {}".format(key_hex))
    return key_hex
#    return PublicKey.from_string(key_bytes)
#    return PublicKey.from_secret(bytes.fromhex(priv))


def pub_to_eth_address(public_key):
    public_key_bytes = codecs.decode(public_key, 'hex')
    return Web3.toChecksumAddress("{}".format(Web3.keccak(public_key_bytes)[-20:].hex()))

#print(eth_address_from_compressed_pubkey_hex('02a97f5c0c43fb54328bac4a1d2ec28c1c2675bbd71862774660b95570085640ed'))
#print(pub_to_dgld_address('02a97f5c0c43fb54328bac4a1d2ec28c1c2675bbd71862774660b95570085640ed'))
wif=('TgR3YEUGYUzZ5wg4RadMMdFYDrMqxEZL5XxgAKefsBjhXw7ogFvd')
raw_priv=bitcoin.decode_privkey(wif,'wif_compressed')
raw_priv_hex=hex(raw_priv)
print("raw_priv: {}".format(raw_priv))
print("raw_priv_hex: {} length: {}".format(raw_priv_hex, len(raw_priv_hex)))
code=0
while True:
    priv_enc=bitcoin.encode_privkey(raw_priv,'wif_compressed',code)
    if priv_enc == wif:
        print("{}".format(code))
        break
    code=code+1
#priv=dgld_wif_compressed_to_privkey('TgR3YEUGYUzZ5wg4RadMMdFYDrMqxEZL5XxgAKefsBjhXw7ogFvd')
print("raw_priv: {}".format(raw_priv))
print("priv_enc: {}".format(priv_enc))
pub=bitcoin.privtopub(wif)
pub_enc=bitcoin.encode_pubkey(pub, 'hex')
addr=bitcoin.pubtoaddr(pub, 38)
addr_enc=bitcoin.pubtoaddr(pub_enc, 38)
print("addr: {}".format(addr))
print("addr_enc: {}".format(addr_enc))
#pub_compressed=priv_to_compressed_pub(priv)
print("pub: {}".format(pub))
print("pub_enc: {}".format(pub_enc))
#print("pub compressed: {}".format(pub_compressed))
#addr=pub_to_eth_address(pub)
#print("eth: {}".format(addr))
#dgld_addr=pub_to_dgld_address(pub)
#print("dgld: {}".format(dgld_addr))

acct = Account.from_key(raw_priv)
acct_addr = acct.address
print("acct_address from private key: {}".format(acct.address))

#Next: go from a compressed public key to the correct ethereum address


expected_compressed_pub='02d1a8d88939fe709a9008b9f32d0408985521ad52d7133ffa4ca150fe0fa23846'
