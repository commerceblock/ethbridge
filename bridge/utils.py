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
import codecs
import bitcoin
from eth_account import Account
from eth_keys import KeyAPI


class MalformedPoint(Exception):
    pass

class InvalidKey(Exception):
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
    return point_to_pubkey_bytes(Point(curve.curve, x, y, order))
    
def pub_to_dgld_address(pubkey):
    return bitcoin.pubkey_to_address(pubkey, 38)

def wif_to_priv_hex(wif, fmt='wif_compressed'):
    priv = bitcoin.decode_privkey(wif,fmt)
    return bitcoin.encode_privkey(priv, 'hex')

def wif_to_priv_bytes(wif, fmt='wif_compressed'):
    priv = bitcoin.decode_privkey(wif,fmt)
    return bitcoin.encode_privkey(priv, 'bin')

def priv_bytes_to_dgld_wif(priv):
    return bitcoin.encode_privkey(raw_priv,'wif_compressed',52)

wif='TgR3YEUGYUzZ5wg4RadMMdFYDrMqxEZL5XxgAKefsBjhXw7ogFvd'
raw_priv=wif_to_priv_bytes(wif)
#pub_from_wif=bitcoin.encode_pubkey(bitcoin.privtopub(raw_priv), 'bin')
#addr=pub_to_dgld_address(pub_from_wif)
#print("{}".format(addr))
#assert(addr == 'GS54T2ATJ4Cxj7xH9EXg9w8WHzHU4CjGCm')

acct = Account.from_key(raw_priv)
acct_addr = acct.address
eth_addr='0xFdF6bEf89DaA1d435bF2987d111B0a24aFF0De76'
assert(acct_addr == eth_addr)

def wif_to_eth_address(wif):
    pub = wif_to_pub_bytes(wif)
    return pub_bytes_to_eth_address(pub)

def priv_bytes_to_eth_address(priv):
    pub=priv_bytes_to_pub(priv)
    print(pub)
    return pub_bytes_to_eth_address(pub)

def wif_compressed_to_priv_bytes(wif):
    bitcoin.encode_privkey(bitcoin.decode_privkey(wif,'wif_compressed'), 'bin')

def priv_bytes_to_wif(priv):
    decoded=bitcoin.decode_privkey(priv,'bin')
    return bitcoin.encode_privkey(decoded, 'wif_compressed')

def wif_to_pub_bytes(wif):
    pub=bitcoin.privtopub(wif)
    print("wif_to_pub_bytes: pub: {}".format(pub))
    return bitcoin.encode_pubkey(pub, 'bin')

def priv_bytes_to_pub(priv):
    print(priv)
    wif=priv_bytes_to_wif(priv)
    print(wif)
    return wif_to_pub(wif)
    
def pub_bytes_to_eth_address(var):
    pub=var
    if len(pub) == 65:
        if pub[0] != 4:
            raise InvalidKey("unrecognised public key format for key: {}".format(pub))
        pub=pub[1:]
    if len(pub) != 64:
        print("Uncompressing pub: {}".format(pub))
        pub = uncompress(pub)
    pk = KeyAPI().PublicKey(pub)
    return pk.to_checksum_address()

def point_to_pubkey_bytes(point: Point):
    result =  bytearray(bytes.fromhex(hex(point.x())[2:]))
    result.extend(bytearray(bytes.fromhex(hex(point.y())[2:])))
    return result

#1: DGLD public key to ethereum address

pub_compressed='02d1a8d88939fe709a9008b9f32d0408985521ad52d7133ffa4ca150fe0fa23846'
addr=pub_bytes_to_eth_address(bytes.fromhex(pub_compressed))
assert(addr == eth_addr)

