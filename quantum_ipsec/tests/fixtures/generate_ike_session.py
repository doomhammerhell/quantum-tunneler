"""Independent deterministic RFC 7296/5282 fixture. Requires cryptography.
Run from any directory; writes ike_session.hex beside this script.
Keys are public test constants, never production credentials.
"""
from pathlib import Path
from struct import pack
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def prf(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def chain(items):
    return b''.join(bytes([items[n+1][0] if n+1 < len(items) else 0, 0])
                    + pack('!H', len(body)+4) + body
                    for n, (_, body) in enumerate(items))


def header(response, auth, size):
    return pack('!QQBBBBII', 1, 2 if response or auth else 0,
                46 if auth else 33, 0x20, 35 if auth else 34,
                0x20 if response else 8, int(auth), size)


proposal = bytes.fromhex('0000002401010003 0300000c01000014800e0100 0300000802000005 000000080400001f')
a = X25519PrivateKey.from_private_bytes(bytes(range(1,33)))
b = X25519PrivateKey.from_private_bytes(bytes(range(33,65)))
ni, nr = bytes([0x11])*32, bytes([0x22])*32
messages = []
for response, private, nonce in [(False,a,ni),(True,b,nr)]:
    items = [(33,proposal),(34,bytes.fromhex('001f0000')+private.public_key().public_bytes_raw()),(40,nonce)]
    if response:
        items.append((41,bytes.fromhex('01004022')))
    body = chain(items)
    messages.append(header(response,False,28+len(body))+body)
seed = ni + nr + pack('!QQ',1,2)
skeyseed = prf(ni+nr,a.exchange(b.public_key()))
material, previous = b'', b''
for counter in range(1,7):
    previous = prf(skeyseed,previous+seed+bytes([counter]))
    material += previous
for response, name, nonce, initial, skp, ske in [
    (False,b'client',nr,messages[0],material[104:136],material[32:68]),
    (True,b'server',ni,messages[1],material[136:168],material[68:104]),
]:
    identity = bytes([11,0,0,0])+name
    tag = prf(prf(bytes([7])*32,b'Key Pad for IKEv2'),initial+nonce+prf(skp,identity))
    first = 36 if response else 35
    plain = chain([(first,identity),(39,bytes([2,0,0,0])+tag)])+b'\0'
    size = 32+8+len(plain)+16
    aad = header(response,True,size)+bytes([first,0])+pack('!H',size-28)
    iv = bytes(8)
    messages.append(aad+iv+AESGCM(ske[:32]).encrypt(ske[32:]+iv,plain,aad))
Path(__file__).with_name('ike_session.hex').write_text('\n'.join(m.hex() for m in messages)+'\n')

# Independent CREATE_CHILD_SA and ESP fixtures, with fresh nonces and IV 1.
from ipaddress import IPv4Address

def ts(ip):
    host = IPv4Address(ip).packed
    return bytes.fromhex('01000000 07000010 0000ffff') + host + host


def esp_proposal(spi):
    return bytes.fromhex('0000002001030402') + pack('!I', spi) + bytes.fromhex('0300000c01000014800e0100 0000000805000000')


child_ni, child_nr = bytes([0x33])*32, bytes([0x44])*32
child_messages = []
for response, spi, nonce, ske in [(False,256,child_ni,material[32:68]),(True,257,child_nr,material[68:104])]:
    plain = chain([(33,esp_proposal(spi)),(40,nonce),(44,ts('10.0.0.1')),(45,ts('10.0.0.2'))])+b'\0'
    size = 32+8+len(plain)+16
    aad = pack('!QQBBBBII',1,2,46,0x20,36,0x20 if response else 8,2,size)+bytes([33,0])+pack('!H',size-28)
    iv = pack('!Q',1)
    child_messages.append(aad+iv+AESGCM(ske[:32]).encrypt(ske[32:]+iv,plain,aad))
keymat, previous = b'', b''
for counter in range(1,4):
    previous = prf(material[:32],previous+child_ni+child_nr+bytes([counter]))
    keymat += previous


def ip_packet(source, dest):
    header = bytearray(bytes.fromhex('450000180000400040110000')+IPv4Address(source).packed+IPv4Address(dest).packed)
    total = sum(int.from_bytes(header[n:n+2],'big') for n in range(0,20,2))
    while total >> 16:
        total = (total & 0xffff)+(total >> 16)
    header[10:12] = pack('!H',(~total)&0xffff)
    return bytes(header)+b'test'


for spi, traffic, source, dest in [(257,keymat[:36],'10.0.0.1','10.0.0.2'),(256,keymat[36:72],'10.0.0.2','10.0.0.1')]:
    packet = ip_packet(source,dest)
    aad, iv = pack('!II',spi,1),pack('!Q',1)
    padding = (4-(len(packet)+2)%4)%4
    protected = packet+bytes(range(1,padding+1))+bytes([padding,4])
    child_messages.extend([packet,aad+iv+AESGCM(traffic[:32]).encrypt(traffic[32:]+iv,protected,aad)])
Path(__file__).with_name('ike_child.hex').write_text('\n'.join(m.hex() for m in child_messages)+'\n')
