from binascii import unhexlify
b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# some preps for b58encoder
iseq = lambda s: s
bseq = bytes
buffer = lambda s: s.buffer

def b58encode_int(i, default_one=True):
    '''Encode an integer using Base58'''
    if not i and default_one:
        return b58_digits[0]
    string = ""
    while i:
        i, idx = divmod(i, 58)
        string = b58_digits[idx] + string
    return string

def b58encode(v):
    '''Encode a string using Base58'''
    if not isinstance(v, bytes):
        raise TypeError("a bytes-like object is required, not '%s'" %
                        type(v).__name__)
    origlen = len(v)
    v = v.lstrip(b'\0')
    newlen = len(v)

    p, acc = 1, 0
    for c in iseq(reversed(v)):
        acc += p * c
        p = p << 8

    result = b58encode_int(acc, default_one=False)
    return (b58_digits[0] * (origlen - newlen) + result)

def b58decode(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise 'invalid base 58 format with invalid character'
            
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]: pad += 1
        else: break
    return b'\x00' * pad + res