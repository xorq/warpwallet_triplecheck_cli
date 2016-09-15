#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import hashlib
import hmac
from struct import Struct
from itertools import izip, starmap
from operator import xor
import re
import sys
P = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx,Gy)
A = 0

def pbkdf2_hex(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Like :func:`pbkdf2_bin` but returns a hex encoded string."""
    return pbkdf2_bin(data, salt, iterations, keylen, hashfunc).encode('hex')


def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`.  It iterates `iterations` time and produces a
    key of `keylen` bytes.  By default SHA-1 is used as hash function,
    a different hashlib `hashfunc` can be provided.
    """
    hashfunc = hashfunc or hashlib.sha256
    mac = hmac.new(data, None, hashfunc)
    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())
    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = list(starmap(xor, izip(rv, u)))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen]

_pack_int = Struct('>I').pack

def hashy(password,salt,N=18,p=1,r=8,buflen=32):
	

	program_str = 'java -Xmx512m'
	#args = '\"'+password+'\x01'+'\" \"'+salt+'\x01'+'\" '+str(N)+' '+str(p)+' '+str(r)+' '+str(buflen)
	args = '\"'+password+'\x01'+'\"'+' '+'\"'+salt+'\x01'+'\"'+' '+str(N)+' '+str(r)+' '+str(p)+' '+str(buflen)
	file_to_run = 'scrypto'
	cmd_str = ''.join([program_str, ' ', file_to_run, ' ', args])
	result=os.popen(cmd_str).read()
	
	#print 'scrypt parameters (Passphrase,salt(blank),N,p,r,buflen):',args
	pbk=pbkdf2_bin(password+'\x02', salt+'\x02',iterations=2**16,keylen=32)
	pbk=int(pbk.encode('hex'),16)

	scrypt=int(result,16)
	resu=hex((scrypt^pbk))[2:-1]
	if len(resu)%2==1:
		return '0'+resu
	else:
		return resu



def encode_privkey(priv,formt):
    if not isinstance(priv,(int,long)):
		return encode_privkey(decode_privkey(priv),formt)
    if formt == 'decimal': return priv
    elif formt == 'bin': return encode(priv,256,32)
    elif formt == 'bin_compressed': return encode(priv,256,32)+'\x01'
    elif formt == 'hex': return encode(priv,16,64)
    elif formt == 'hex_compressed': return encode(priv,16,64)+'01'
    elif formt == 'wif': return bin_to_b58check(encode(priv,256,32),128)
    elif formt == 'wif_compressed': return bin_to_b58check(encode(priv,256,32)+'\x01',128)
    else: raise Exception("Invalid format!")


def decode_privkey(priv,formt=None):
    if not formt: formt = get_privkey_format(priv)
    if formt == 'decimal': return priv
    elif formt == 'bin': return decode(priv,256)
    elif formt == 'bin_compressed': return decode(priv[:32],256)
    elif formt == 'hex': return decode(priv,16)
    elif formt == 'hex_compressed': return decode(priv[:64],16)
    else:
        bin_p = b58check_to_bin(priv)
        if len(bin_p) == 32: return decode(bin_p,256)
        elif len(bin_p) == 33: return decode(bin_p[:32],256)
        else: raise Exception("WIF does not represent privkey")

def get_privkey_format(priv):
    if isinstance(priv,(int,long)): return 'decimal'
    elif len(priv) == 32: return 'bin'
    elif len(priv) == 33: return 'bin_compressed'
    elif len(priv) == 64: return 'hex'
    elif len(priv) == 66: return 'hex_compressed'
    else:
        bin_p = b58check_to_bin(priv)
        if len(bin_p) == 32: return 'wif'
        elif len(bin_p) == 33: return 'wif_compressed'
        else: raise Exception("WIF does not represent privkey")

def decode(string,base):
   base = int(base)
   code_string = get_code_string(base)
   result = 0
   if base == 16: string = string.lower()
   while len(string) > 0:
      result *= base
      result += code_string.find(string[0])
      string = string[1:]
   return result

def get_code_string(base):
   if base == 2: return '01'
   elif base == 10: return '0123456789'
   elif base == 16: return "0123456789abcdef"
   elif base == 58: return "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   elif base == 256: return ''.join([chr(x) for x in range(256)])
   else: raise ValueError("Invalid base!")


def bin_to_b58check(inp,magicbyte=0):
    inp_fmtd = chr(int(magicbyte)) + inp
    leadingzbytes = len(re.match('^\x00*',inp_fmtd).group(0))
    checksum = bin_dbl_sha256(inp_fmtd)[:4]
    return '1' * leadingzbytes + changebase(inp_fmtd+checksum,256,58)

def encode(val,base,minlen=0):
   base, minlen = int(base), int(minlen)
   code_string = get_code_string(base)
   result = ""   
   while val > 0:
      result = code_string[val % base] + result
      val /= base
   if len(result) < minlen:
      result = code_string[0]*(minlen-len(result))+result
   return result

def bin_dbl_sha256(string):
   return hashlib.sha256(hashlib.sha256(string).digest()).digest()

def changebase(string,frm,to,minlen=0):
   return encode(decode(string,frm),to,minlen)

def privkey_to_address(priv,magicbyte=0):
    return pubkey_to_address(privkey_to_pubkey(priv),magicbyte)

def pubkey_to_address(pubkey,magicbyte=0):
   if isinstance(pubkey,(list,tuple)):
       pubkey = encode_pubkey(pubkey,'bin')
   if len(pubkey) in [66,130]:
       return bin_to_b58check(bin_hash160(pubkey.decode('hex')),magicbyte)
   return bin_to_b58check(bin_hash160(pubkey),magicbyte)

def privkey_to_pubkey(privkey):
    f = get_privkey_format(privkey)
    privkey = decode_privkey(privkey,f)
    if privkey == 0 or privkey >= N:
        raise Exception("Invalid privkey")
    if f in ['bin','bin_compressed','hex','hex_compressed','decimal']:
        return encode_pubkey(base10_multiply(G,privkey),f)
    else:
        return encode_pubkey(base10_multiply(G,privkey),f.replace('wif','hex'))

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*',inp).group(0))
    data = '\x00' * leadingzbytes + changebase(inp,58,256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]


def encode_pubkey(pub,formt):
    if not isinstance(pub,(tuple,list)):
        pub = decode_pubkey(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return '\x04' + encode(pub[0],256,32) + encode(pub[1],256,32)
    elif formt == 'bin_compressed': return chr(2+(pub[1]%2)) + encode(pub[0],256,32)
    elif formt == 'hex': return '04' + encode(pub[0],16,64) + encode(pub[1],16,64)
    elif formt == 'hex_compressed': return '0'+str(2+(pub[1]%2)) + encode(pub[0],16,64)
    elif formt == 'bin_electrum': return encode(pub[0],256,32) + encode(pub[1],256,32)
    elif formt == 'hex_electrum': return encode(pub[0],16,64) + encode(pub[1],16,64)
    else: raise Exception("Invalid format!")

def base10_multiply(a,n):
  if isinf(a) or n == 0: return (0,0)
  if n == 1: return a
  if n < 0 or n >= N: return base10_multiply(a,n%N)
  if (n%2) == 0: return base10_double(base10_multiply(a,n/2))
  if (n%2) == 1: return base10_add(base10_double(base10_multiply(a,n/2)),a)

def isinf(p): return p[0] == 0 and p[1] == 0

def base10_add(a,b):
  if isinf(a): return b[0],b[1]
  if isinf(b): return a[0],a[1]
  if a[0] == b[0]: 
    if a[1] == b[1]: return base10_double((a[0],a[1]))
    else: return (0,0)
  m = ((b[1]-a[1]) * inv(b[0]-a[0],P)) % P
  x = (m*m-a[0]-b[0]) % P
  y = (m*(a[0]-x)-a[1]) % P
  return (x,y)
  
def base10_double(a):
  if isinf(a): return (0,0)
  m = ((3*a[0]*a[0]+A)*inv(2*a[1],P)) % P
  x = (m*m-2*a[0]) % P
  y = (m*(a[0]-x)-a[1]) % P
  return (x,y)

def inv(a,n):
  lm, hm = 1,0
  low, high = a%n,n
  while low > 1:
    r = high/low
    nm, new = hm-lm*r, high-low*r
    lm, low, hm, high = nm, new, lm, low
  return lm % n

def bin_hash160(string):
   intermed = hashlib.sha256(string).digest()
   return hashlib.new('ripemd160',intermed).digest()


aal = hashy(sys.argv[1],sys.argv[2])
pkey = encode_privkey((aal),'wif')
print pkey
print privkey_to_pubkey(pkey)
print privkey_to_address(pkey)
#print privkey_to_address(pkey)




