# -*- coding: utf-8 -*-
"""
Created on Wed Jul  4 22:50:47 2018
"""

class InvalidAddress(Exception):
    pass

class Address:
    VERSION_MAP = {
        'legacy': [
            ('P2SH', 5, False),
            ('P2PKH', 0, False),
            ('P2SH-TESTNET', 196, True),
            ('P2PKH-TESTNET', 111, True)
        ],
        'cash': [
            ('P2SH', 8, False),
            ('P2PKH', 0, False),
            ('P2SH-TESTNET', 8, True),
            ('P2PKH-TESTNET', 0, True)
        ]
    }
    MAINNET_PREFIX = 'bitcoincash'
    TESTNET_PREFIX = 'bchtest'

    def _address_type(address_type, version):
        for mapping in Address.VERSION_MAP[address_type]:
            if mapping[0] == version or mapping[1] == version:
                return mapping
        raise InvalidAddress('Could not determine address version')

def _cash_string(address_string):
    if address_string.upper() != address_string and address_string.lower() != address_string:
        raise InvalidAddress('Cash address contains uppercase and lowercase characters')
    address_string = address_string.lower()

    if ':' not in address_string:
        address_string = 'bitcoincash' + ':' + address_string
    prefix, base32string = address_string.split(':')
    decoded = b32decode(base32string)

    if not verify_checksum(prefix, decoded):
        raise InvalidAddress('Bad cash address checksum')

    converted = convertbits(decoded, 5, 8)
    version   = Address._address_type('cash', converted[0])[0]
    
    if prefix == Address.TESTNET_PREFIX:
        version += '-TESTNET'
    payload = converted[1:-6]
    return version, payload, prefix
    
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

def verify_checksum(prefix, payload):
    return polymod(prefix_expand(prefix) + payload) == 0

def b32encode(inputs):
    out = ''
    for char_code in inputs:
        out += CHARSET[char_code]
    return out

def b32decode(inputs):
    out = list()
    for letter in inputs:
        out.append(CHARSET.find(letter))
    return out


def prefix_expand(prefix):
    # as per description, convert "bitcoincash" prefix and, add one 0 at end
    # 0x1f = 31
    return [ord(x) & 0x1f for x in prefix] + [0]

def calculate_cksum(prefix, payload):
    poly = polymod(prefix_expand(prefix) + payload + [0, 0, 0, 0, 0, 0, 0, 0])
    out = list()
    for i in range(8):
        out.append((poly >> 5 * (7 - i)) & 0x1f)
    return out

def polymod(values):
    chk = 1
    generator = [
        (0x01, 0x98f2bc8e61),
        (0x02, 0x79b76d99e2),
        (0x04, 0xf33e5fb3c4),
        (0x08, 0xae2eabe2a8),
        (0x10, 0x1e4f43e470)]
    for value in values:
        top = chk >> 35
        chk = ((chk & 0x07ffffffff) << 5) ^ value
        for i in generator:
            if top & i[0] != 0:
                chk ^= i[1]
    return chk ^ 1


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret