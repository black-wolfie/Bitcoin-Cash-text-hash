# -*- coding: utf-8 -*-
"""
Created on Thu Aug  9 13:48:02 2018
"""

import hashlib
import ecdsa

from binascii  import hexlify, unhexlify
from BCH_cash_addr_tools import _cash_string, convertbits, calculate_cksum, b32encode
from b58 import b58encode, b58decode

bfh = bytes.fromhex
hfu = hexlify

# secp256k1 curve parameters:
# secp256k1 parameters, http://www.oid-info.com/get/1.3.132.0.10
_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_r  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_b  = 0x0000000000000000000000000000000000000000000000000000000000000007
_a  = 0x0000000000000000000000000000000000000000000000000000000000000000
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp( _p, _a, _b )
generator_secp256k1 = ecdsa.ellipticcurve.Point(curve_secp256k1, _Gx, _Gy, _r )

_oid_secp256k1 = (1,3,132,0,10)
SECP256k1 = ecdsa.curves.Curve("SECP256k1", curve_secp256k1, generator_secp256k1, _oid_secp256k1 )
_order = generator_secp256k1.order()

#%%
# basic functions needed
def bh2u(x):
    """
    str with hex representation of a bytes-like object
    >>> x = bytes((1, 2, 10))
    >>> bh2u(x)
    '01020A'
    :param x: bytes
    :rtype: str
    """
    return hfu(x).decode('ascii')

def rev_hex(s):
    return bh2u(bfh(s)[::-1])

def int_to_hex(i, length=1):
    assert isinstance(i, int)
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

#%%
_locktime = 0
_nLocktime = int_to_hex(_locktime, 4)

#%%
def sha256_ripemd160(public_key):
    md160 = hashlib.new('ripemd160')
    md160.update(hashlib.sha256(public_key).digest())
    return md160.digest()

def sha256d(data):
    # data must be encoded before hashing!
    # first hash, encode the string message data
    sha256_1st = hashlib.sha256(data).digest()
    # the result of the first hash is already a bytes-object
    sha256_2nd = hashlib.sha256(sha256_1st).digest()
    return sha256_2nd

def serialize_outpoint(txin):
    return bh2u(bfh(txin['tx_hash'])[::-1]) + int_to_hex(txin['tx_output_n'], 4)

def var_int(i):
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    if i < 0xfd:
        return int_to_hex(i)
    elif i <= 0xffff:
        return "fd"+int_to_hex(i,2)
    elif i <= 0xffffffff:
        return "fe"+int_to_hex(i,4)
    else:
        return "ff"+int_to_hex(i,8)

def pay_script(UTXO_address_pay):
    # assuming it's the standard bitcoincash:q... address with RipeMD160 hash for pubkey
    # 76a917 is the OP_DUP OP_HASH160
    # 88ac is   the OP_EQUALVERIFY OP_CHECKSIG
    addr = UTXO_address_pay
    addr_script = ''.join(
            int_to_hex(_cash_string(addr)[1][i]) for i in range(len(_cash_string(addr)[1])))
    s = ("76a914"+ addr_script + "88ac")
    return s

def serialize_output(output):
    amount, addr = output
    if addr[:2] != '6a':
        s = int_to_hex(amount, 8)
        script = pay_script(addr)
        s += var_int(len(script)//2)
        s += script
    else:
        s = int_to_hex(amount, 8) + var_int(len(addr)//2) + addr
    return s

def hash_str_reverse(a):
    # reverse, every two character at a time!
    reversed_str = "".join(reversed([a[i:i+2] for i in range(0, len(a), 2)]))
    return reversed_str

def nHashType():
    '''Hash type in hex.'''
    SIGHASH_FORKID = 0x40
    FORKID = 0x000000
    return 0x01 | (SIGHASH_FORKID + (FORKID << 8))

def encode_point(pubkey, compressed=False):
    p = pubkey.pubkey.point
    x_str = ecdsa.util.number_to_string(p.x(), _order)
    y_str = ecdsa.util.number_to_string(p.y(), _order)
    
    if compressed:
        return chr(2 + (p.y() & 1)).encode() + x_str
    else:
        return chr(4).encode() + x_str + y_str

def sign(b58_priv_key, serialized_preimage):
    # base58 decode the private key string
    encoded_priv_key_bytes = b58decode(b58_priv_key)
    encoded_priv_key_hex_string = hfu(encoded_priv_key_bytes)

    secret_hex_string = ''

    if b58_priv_key[0] == 'L' or b58_priv_key[0] == 'K':
        # if private key (hex) starts with L or K, length should be 76
        assert len(encoded_priv_key_hex_string) == 76

        # strip leading 0x08, 0x01 compressed flag, checksum
        # encoded_priv_key_hex_string[-10:] is:
        # compression flag (2 char), and checksum (8 char)
        secret_hex_string = encoded_priv_key_hex_string[2:-10]

    elif b58_priv_key[0] == '5':
        assert len(encoded_priv_key_hex_string) == 74

        # strip leading 0x08 and checksum
        # encoded_priv_key_hex_string[-10:] is: checksum (8 char)
        secret_hex_string = encoded_priv_key_hex_string[2:-8]

    else:
        raise BaseException(
                "error: private must start with 5 if uncompressed or "+
                "L/K for compressed")
        
    # make sure the secret number is smaller than 2**256, extract the secret number
    # secret number is used to construct the private key (ecdsa-compatible)
    secret          = int(secret_hex_string, 16)
    assert secret < 2**256
    
    pre_hash = sha256d(bfh(serialized_preimage))
    
    # obtain private and public key
    private_key = ecdsa.SigningKey.from_secret_exponent(secret, curve = SECP256k1 )
    public_key = private_key.get_verifying_key()
    
    # create signature using the created private key, and the hashed pre-image
    sig = private_key.sign_digest_deterministic(pre_hash, hashfunc = hashlib.sha256,
                                                sigencode = ecdsa.util.sigencode_der)
    
    # update r, and s, make sure they comply with consensus rule
    r, s = ecdsa.util.sigdecode_der(sig, _order)
    
    if s > _order / 2:
        s = _order - s
    else:
        s = s
    
    sig = ecdsa.util.sigencode_der(r, s, _order)
    
    # verifying that the signature is valid
    assert public_key.verify_digest(sig, pre_hash, sigdecode = ecdsa.util.sigdecode_der)
    
    # hexlifying the signature
    signature_i = bh2u(sig) + int_to_hex(nHashType() & 255, 1)
    
    public_key_byte = encode_point(public_key, compressed=True)
    return signature_i, public_key_byte
    # output defined here! OP_RETURN needs to be added in later
    # consolidate all coins into itself (and then add in the OP_RETURN)
    # edit the the sum to pay fees

def priv_key_to_b58_addr(b58_priv_key):
    # base58 decode the private key string
    encoded_priv_key_bytes = b58decode(b58_priv_key)
    encoded_priv_key_hex_string = hfu(encoded_priv_key_bytes)

    secret_hex_string = ''

    if b58_priv_key[0] == 'L' or b58_priv_key[0] == 'K':
        # if private key (hex) starts with L or K, length should be 76
        assert len(encoded_priv_key_hex_string) == 76

        # strip leading 0x08, 0x01 compressed flag, checksum
        # encoded_priv_key_hex_string[-10:] is:
        # compression flag (2 char), and checksum (8 char)
        secret_hex_string = encoded_priv_key_hex_string[2:-10]

    elif b58_priv_key[0] == '5':
        assert len(encoded_priv_key_hex_string) == 74

        # strip leading 0x08 and checksum
        # encoded_priv_key_hex_string[-10:] is: checksum (8 char)
        secret_hex_string = encoded_priv_key_hex_string[2:-8]

    else:
        raise BaseException(
                "error: private must start with 5 if uncompressed or "+
                "L/K for compressed")
        
    # make sure the secret number is smaller than 2**256, extract the secret number
    # secret number is used to construct the private key (ecdsa-compatible)
    
    secret          = int(secret_hex_string, 16)
    assert secret < 2**256
    
    # obtain private and public key
    private_key = ecdsa.SigningKey.from_secret_exponent(secret, curve = SECP256k1 )
    public_key = private_key.get_verifying_key()
    
    addrtype = 0
    
    public_key_byte = encode_point(public_key, compressed=True)
    h160 = sha256_ripemd160(public_key_byte)
    vh160 = chr(addrtype).encode() + h160
    
    # checksum is the last 4 bytes of the double SHA256 hash
    hash_1st = hashlib.sha256(vh160).digest()
    hash_2nd = hashlib.sha256(hash_1st).digest()
    addr = vh160 + hash_2nd[0:4]
    
    return b58encode(addr)

def serialize_preimage(UTXO_list, i, nVersion, outputs, UTXO_address_i):
    
    # utxo_list listing, this has been verified to be correct
    hashPrevouts = bh2u(sha256d(bfh(''.join(serialize_outpoint(txin) for txin in UTXO_list))))
    
    # in BIP143 example:
    # bh2u(sha256d(bfh("eeffffffffffffff"))) = 
    # 52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339
    hashSequence = bh2u(sha256d(bfh(''.join(
            int_to_hex(txin.get('sequence', 0xffffffff - 1), 4) for txin in UTXO_list))))
    
    # hashOutputs
    # BIP143 example:
    # bh2u(sha256d(bfh("202cb206000000001976a9148280b37df378db99f66f85c95a783a
    # 76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac")))
    hashOutputs  = bh2u(sha256d(bfh(''.join(serialize_output(o) for o in outputs))))
    
    # outpoint is the last transaction input
    outpoint = serialize_outpoint(UTXO_list[i])
    
    # our situation is unique, we are spending all address A coins and send 
    # them into address A
    preimage_script = pay_script(UTXO_address_i)
    scriptCode = var_int(len(preimage_script) // 2) + preimage_script
    
    # amount, depends on which utxo you are using
    amount = int_to_hex(UTXO_list[i]['value'], 8)
    nSequence = int_to_hex(UTXO_list[i].get('sequence', 0xffffffff - 1), 4)
    
    nHashType_image = int_to_hex(nHashType(), 4)
    
    preimage = (nVersion + hashPrevouts + hashSequence + outpoint + scriptCode + 
                amount + nSequence + hashOutputs + _nLocktime + nHashType_image)
    #print("")
    #print("preimage is: ")
    #print(preimage)
    return preimage

def serialize_signed_txn(sig_list, utxo_input_list, outputs, pub_key_list, nVersion):
    serialized_signed_txn   = ""
    
    for i, txin in enumerate(utxo_input_list):
        signed_input = ""
        signed_input = var_int(len(pub_key_list[i])//2)+ pub_key_list[i] + signed_input
        signed_input = var_int(len(sig_list[i])//2) + sig_list[i] + signed_input
        signed_input = var_int(len(signed_input) //2) + signed_input
        signed_input = serialize_outpoint(txin) + signed_input
        signed_input = signed_input + int_to_hex(txin.get('sequence', 0xffffffff - 1))
        
        serialized_signed_txn = serialized_signed_txn + signed_input
        
    serialized_signed_txn = nVersion + var_int(len(utxo_input_list)) + serialized_signed_txn
    return serialized_signed_txn

def public_key_to_Cash_Addr(public_key):
    # public key is hashed with SHA256 and RipeMD160
    h160 = sha256_ripemd160(public_key)
  
    # here is where Cash Addr differs from Bitcoin mainnet
    # double SHA256 hash is not used for checksum
    # you obtain the payload, then apply base32 encoder to it
    
    # payload = prefix + h160 hash + checksum
    addrtype = 0
    version_bit = chr(addrtype).encode()
    prefix = "bitcoincash"
    payload = version_bit + h160
    
    # converting bits
    payload = convertbits(payload, 8, 5)
    checksum = calculate_cksum(prefix, payload)
    
    # https://github.com/oskyk/cashaddress/blob/master/cashaddress/convert.py
    return prefix + ':' + b32encode(payload + checksum)

def b58_pri_key_to_cash_addr(b58_priv_key_1):
    encoded_priv_key_bytes = b58decode(b58_priv_key_1)
    encoded_priv_key_hex_string = hfu(encoded_priv_key_bytes)

    secret_hex_str = ''

    if b58_priv_key_1[0] == 'L' or b58_priv_key_1[0] == 'K':
        if not len(encoded_priv_key_hex_string) == 76:
            cash_addr = "private key is not valid"
            return cash_addr
        else:
            secret_hex_str = encoded_priv_key_hex_string[2:-10]

    elif b58_priv_key_1[0] == '5':
        if not len(encoded_priv_key_hex_string) == 74:
            cash_addr = "private key is not valid"
            return cash_addr
        else:
            secret_hex_str = encoded_priv_key_hex_string[2:-8]
    else:
        cash_addr = "private key is not valid"
        return cash_addr
        
    secret = int(secret_hex_str, 16)
    
    # check private_key and checksum
    # make sure secret < 2**256
    if not secret < 2**256:
        cash_addr = "private key is not valid"
        return cash_addr
    
    if not hfu(sha256d(unhexlify(encoded_priv_key_hex_string[:68]
            )))[:8] == encoded_priv_key_hex_string[-8:].lower():
        cash_addr = "private key is not valid"
        return cash_addr
    
    private_key = ecdsa.SigningKey.from_secret_exponent(secret, curve = SECP256k1 )
    public_key = private_key.get_verifying_key()
    
    public_key_byte = encode_point(public_key, compressed=True)
    cash_addr = public_key_to_Cash_Addr(public_key_byte)
    return cash_addr

# creating signatures and public keys
def query_txn(pri_key):
#    # API version: blockchair.com
#    import pandas as pd
#    cash_address   = b58_pri_key_to_cash_addr(pri_key)
#    UTXO_address_1 = cash_address.split(sep=":")[1]
#    
#    url_utxo_1 = ("https://api.blockchair.com/bitcoin-cash/outputs?fields="+
#                  "transaction_hash,index,value,recipient,is_spent&q=recipient("+
#                  UTXO_address_1 + "),is_spent(false)&export=csv")
#    
#    utxo_tb   = pd.read_csv(url_utxo_1)
#    
#    if utxo_tb.shape[0] == 0:
#        return cash_address, []
#    
#    else:
#        utxo_tb.rename(columns={"transaction_hash": "tx_hash","index":"tx_output_n"}, 
#                       inplace = True)
#        utxo_list = utxo_tb.to_dict('record')
#        return cash_address, utxo_list

    # API version: BTC.com version
    import requests as rqs
    cash_address   = b58_pri_key_to_cash_addr(pri_key)
    b58_address    = priv_key_to_b58_addr(pri_key)
    
    url_utxo_1 = ("https://bch-chain.api.btc.com/v3/address/" + b58_address +"/unspent")
    r         = rqs.get(url_utxo_1)
    r_content = r.json()
    
    if r_content['err_no'] == 1:
        return cash_address, ("error_received")
    else:
        utxo_list = r_content['data']['list']
        return cash_address, utxo_list
    
def op_return(text_str):
    op_return_SPK = hfu(text_str.encode()).decode()
    op_return_SPK = var_int(len(op_return_SPK)//2) + op_return_SPK
    op_return_SPK = var_int(len("sha256d")) + hfu("sha256d".encode()).decode() + op_return_SPK
    
    # 0x61 = 97, a number that is unlikely to be used by anyone else
    # 0x01 = 01, potentially leave room for future upgrade, 01 = text, 00 = review
    # 0x02 = 02, the lenth of '6101'
    op_return_SPK = "026101" + op_return_SPK
    
    # 6a is the code for OP_RETURN
    op_return_SPK = '6a' + op_return_SPK
    return op_return_SPK

# final function for serializing the transaction
def txn(utxo_list, UTXO_address_1, b58_pri_key, text):
    i         = 0
    nVersion  = '01000000'
    fees      = 0    # initial fees and size_txn are set to very small and large
    
    for ii in range(2):
        outputs   = [[sum([utxo['value'] for utxo in utxo_list]) - fees, UTXO_address_1],
                     [0, op_return(hfu(sha256d(text.encode())).decode())]]

        if ":" not in UTXO_address_1:
            UTXO_address_1 = ("bitcoincash:" + UTXO_address_1)
        
        preimage_list = []
        sig_list      = []
        pub_key_list  = []
        
        for i, utxo in enumerate(utxo_list):
            preimage_list += [serialize_preimage(utxo_list, i, nVersion, outputs, UTXO_address_1)]

        for i, preimage_i in enumerate(preimage_list):
            signature, encoded_pub_key = sign(b58_pri_key, preimage_i)
            pub_key_list += [hfu(encoded_pub_key).decode()]
            sig_list += [signature]
        
        signed_txn = serialize_signed_txn(sig_list, utxo_list, outputs, pub_key_list, nVersion)
        
        # add in outputs
        signed_txn = signed_txn + var_int(len(outputs))
        for j, output in enumerate(outputs):
            signed_txn = signed_txn + serialize_output(output)
        
        # _nLocktime
        signed_txn = signed_txn + _nLocktime
        size_txn = len(signed_txn) // 2
        
        if ii == 0:
            fees = int(size_txn * 1.05)
    
        # check dust level
    assert fees/size_txn > 1.0
    return signed_txn

#%%
from tkinter import Tk, Label, Button, Entry, IntVar, END, W, E, scrolledtext, INSERT

class BCH_write_onchain_GUI:

    def __init__(self, master):
        self.master = master
        master.title("Bitcoin Cash onchain hash-recorder")
        
        self.address_string = "please type in a private key, start with L or K"
        
        self.cash_addr = IntVar()
        self.cash_addr.set(self.address_string)
        self.addr_str_label = Label(master, textvariable=self.cash_addr)

        self.label0 = Label(master, text = "+")
        self.label1 = Label(master, text = "private key: ")
        
        self.addr_balance = IntVar()
        self.addr_balance.set("balance:")
        self.label3 = Label(master, textvariable = self.addr_balance)
        self.entry = Entry(master, width = 60)
        
        # lambda: is necessary here
        self.get_cash_addr = Button(master, text = "get signed transaction",
                                command = lambda: self.cash_converter())
        
        self.label4 = Label(master, text = "             ")
        self.label5 = Label(master, text = "insert review text below")
        self.label6 = Label(master, text = "signed transaction below")
        self.scrolled_txt_content0 = scrolledtext.ScrolledText(master, width=35, height=20)
        self.scrolled_txt_content1 = scrolledtext.ScrolledText(master, width=35, height=20)
        self.scrolled_txt_content0.insert(INSERT,
"""\
-----------text-begins-----------




-----------text-ends-------------""")

        self.label7 = Label(master, text = "             ")
        
        # LAYOUT
        self.label0.grid(row=0, column=0, sticky = W)
        self.label1.grid(row=1, column=1, sticky = W)
        self.entry.grid(row=1, column=2, columnspan=3, sticky=W+E)
        
        self.addr_str_label.grid(row=4, column=2, sticky=W)
        self.label3.grid(row = 5, column = 2, sticky = W)
        self.label4.grid(row=6, column=1, sticky = W)
        self.label5.grid(row=8, column=2, sticky = W)
        self.label6.grid(row=8, column=5, sticky = W)
        self.scrolled_txt_content0.grid(row = 9,column = 2, columnspan = 3, sticky = W)
        self.scrolled_txt_content1.grid(row = 9,column = 5, columnspan = 3, sticky = W)
        self.label7.grid(row = 10, column = 1, sticky = W)
        
        self.get_cash_addr.grid(row=11, column=2, sticky=W+E)

    def cash_converter(self):
        if len(str(self.scrolled_txt_content1.get("1.0", "end-1c"))) != 0:
            self.scrolled_txt_content1.delete('1.0', END)
        
        text = str(self.entry.get())
        if len(text) == 0:
            self.address_string = "enter a private key above"
        else:
            self.address_string = (b58_pri_key_to_cash_addr(text))
            self.cash_addr.set(self.address_string)
            
            cash_address, utxo_list = query_txn(text)
            if utxo_list == ("error_received"):
                balance_str = ("error received, most likely the address does not have any Bitcoin Cash")
                self.addr_balance.set(balance_str)
            else:
                balance_str = str(sum([utxo['value'] for utxo in utxo_list])/100)
                balance_str = ("balance: " + balance_str + " bits")
                
                self.addr_balance.set(balance_str)
                text_review = str(self.scrolled_txt_content0.get("1.0", "end-1c"))
                signed_txn = txn(utxo_list, cash_address, text, text_review)
                self.scrolled_txt_content1.insert(INSERT, signed_txn)

        self.entry.delete(0, END)

if __name__ == "__main__":
    root = Tk()
    root.title("Write on Bitcoin Cash onchain")
    root.geometry("1000x700+200+200")
    app = BCH_write_onchain_GUI(root)
    root.mainloop()

