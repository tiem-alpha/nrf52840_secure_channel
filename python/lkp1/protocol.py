"""Strict LKP1 wire codec, client/server handshake, and application AEAD."""
import hashlib
import hmac
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from .cert import Certificate, LOCK, PHONE, sign_raw, verify_raw

HANDSHAKE, HANDSHAKE_ENC, APP_DATA, ALERT = 1, 2, 3, 4
CH, SH, CERT, CV, FIN = 1, 2, 11, 15, 20


class ProtocolError(ValueError):
    pass


def sha(data): return hashlib.sha256(data).digest()
def hm(key, data): return hmac.new(key, data, hashlib.sha256).digest()
def expand(prk, label, ctx, length):
    return HKDFExpand(algorithm=hashes.SHA256(), length=length,
        info=b'LKP1 ' + label.encode() + b'\0' + ctx).derive(prk)
def frame(kind, body):
    if len(body) > 1024: raise ProtocolError('record too long')
    return bytes((1, kind)) + len(body).to_bytes(2, 'big') + body
def unframe(raw, kind):
    if len(raw) < 4 or raw[0] != 1 or raw[1] != kind or int.from_bytes(raw[2:4], 'big') != len(raw)-4 or len(raw)-4 > 1024:
        raise ProtocolError('record framing')
    return raw[4:]
def message(kind, body): return bytes((kind,)) + len(body).to_bytes(2, 'big') + body
def split_messages(raw, kinds):
    out=[]; pos=0
    for kind in kinds:
        if len(raw)-pos < 3 or raw[pos] != kind: raise ProtocolError('handshake order')
        n=int.from_bytes(raw[pos+1:pos+3], 'big'); end=pos+3+n
        if end > len(raw): raise ProtocolError('truncated handshake')
        out.append(raw[pos:end]); pos=end
    if pos != len(raw): raise ProtocolError('handshake trailing bytes')
    return out
def cert_body(chain):
    if not 1 <= len(chain) <= 2: raise ProtocolError('certificate count')
    return bytes((len(chain),)) + b''.join((164).to_bytes(2,'big') + c.encode() for c in chain)
def parse_certs(raw):
    if not raw or not 1 <= raw[0] <= 2: raise ProtocolError('certificate count')
    pos=1; out=[]
    for _ in range(raw[0]):
        if len(raw)-pos < 2 or int.from_bytes(raw[pos:pos+2], 'big') != 164: raise ProtocolError('certificate length')
        pos += 2
        if len(raw)-pos < 164: raise ProtocolError('truncated certificate')
        out.append(Certificate.decode(raw[pos:pos+164])); pos += 164
    if pos != len(raw): raise ProtocolError('certificate trailing bytes')
    return tuple(out)
def nonce(iv, counter):
    return bytes(a^b for a,b in zip(iv, b'\0'*4 + counter.to_bytes(8,'big')))
def seal(key, iv, counter, kind, plaintext):
    header=bytes((1,kind)) + (len(plaintext)+16).to_bytes(2,'big')
    return header + AESGCM(key).encrypt(nonce(iv,counter), plaintext, header)
def open_sealed(key, iv, counter, record, kind):
    body=unframe(record,kind)
    if len(body)<16: raise ProtocolError('short ciphertext')
    return AESGCM(key).decrypt(nonce(iv,counter), body, record[:4])


class _Peer:
    def __init__(self, identity, roots, ephemeral=None, random_nonce=None, now=None):
        self.identity=identity; self.roots=roots
        self.ephemeral=ephemeral or x25519.X25519PrivateKey.generate()
        self.random_nonce=random_nonce or os.urandom(32)
        if len(self.random_nonce)!=32: raise ValueError('nonce length')
        self.messages=[]; self.state='IDLE'; self.now=now
        self.started=time.monotonic(); self.send_seq=0; self.recv_seq=0
    def _deadline(self):
        if time.monotonic()-self.started>10: raise ProtocolError('handshake timeout')
    def _keys(self, peer_pub, c_nonce, s_nonce):
        ss=self.ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub))
        if ss==bytes(32): raise ProtocolError('low-order ephemeral key')
        self.prk=hm(c_nonce+s_nonce,ss)
        ctx=sha(b''.join(self.messages[:2]))
        for name,n in [('c_hs_key',16),('c_hs_iv',12),('s_hs_key',16),('s_hs_iv',12),('c_fin_key',32),('s_fin_key',32)]:
            setattr(self,name,expand(self.prk,name.replace('_',' ').replace('fin key','finished'),ctx,n))
    def _app_keys(self):
        self.master=expand(self.prk,'master',sha(b''.join(self.messages)),32)
        for name,n in [('c2s_key',16),('c2s_iv',12),('s2c_key',16),('s2c_iv',12),('session_id',4)]:
            setattr(self,name,expand(self.master,name.replace('_',' '),b'',n))
        self.prk=None; self.ephemeral=None
        for name in ('c_hs_key','c_hs_iv','s_hs_key','s_hs_iv','c_fin_key','s_fin_key'):
            setattr(self,name,None)
        self.state='OPEN'
        self.opened=time.monotonic()
    def _app_deadline(self):
        if time.monotonic()-self.opened>24*60*60:
            self.state='IDLE'
            raise ProtocolError('session expired')
    def send_app(self, plaintext):
        if self.state!='OPEN' or len(plaintext)>512 or self.send_seq==0xffffffff: raise ProtocolError('application send state')
        self._app_deadline()
        seq=self.send_seq; self.send_seq+=1
        sid_seq=self.session_id+seq.to_bytes(4,'big')
        header=bytes((1,APP_DATA))+(len(plaintext)+24).to_bytes(2,'big')
        key,iv=(self.c2s_key,self.c2s_iv) if isinstance(self,Client) else (self.s2c_key,self.s2c_iv)
        return header+sid_seq+AESGCM(key).encrypt(nonce(iv,seq),plaintext,header+sid_seq)
    def recv_app(self,raw):
        if self.state!='OPEN': raise ProtocolError('application receive state')
        self._app_deadline()
        body=unframe(raw,APP_DATA)
        if len(body)<24 or body[:4]!=self.session_id: raise ProtocolError('session id')
        seq=int.from_bytes(body[4:8],'big')
        if seq!=self.recv_seq or seq==0xffffffff: raise ProtocolError('sequence')
        key,iv=(self.s2c_key,self.s2c_iv) if isinstance(self,Client) else (self.c2s_key,self.c2s_iv)
        plain=AESGCM(key).decrypt(nonce(iv,seq),body[8:],raw[:12])
        if len(plain)>512: raise ProtocolError('application length')
        self.recv_seq+=1
        return plain


class Client(_Peer):
    def start(self):
        if self.state!='IDLE': raise ProtocolError('client state')
        from cryptography.hazmat.primitives import serialization
        pub=self.ephemeral.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.messages=[message(CH,b'\0\1'+pub+self.random_nonce)]
        self.state='SENT_CH'; return frame(HANDSHAKE,self.messages[0])
    def receive_f2(self,clear,encrypted,pinned_id):
        self._deadline()
        if self.state!='SENT_CH': raise ProtocolError('client state')
        (m2,)=split_messages(unframe(clear,HANDSHAKE),(SH,))
        if len(m2)!=69 or m2[3:5]!=b'\0\1': raise ProtocolError('server hello')
        self.messages.append(m2); self._keys(m2[5:37],self.random_nonce,m2[37:69])
        plain=open_sealed(self.s_hs_key,self.s_hs_iv,0,encrypted,HANDSHAKE_ENC)
        m3,m4,m5=split_messages(plain,(CERT,CV,FIN)); self.messages.append(m3)
        pub=self.roots.verify(parse_certs(m3[3:]),LOCK,self.now,True,pinned_id)
        if len(m4)!=67: raise ProtocolError('server signature length')
        verify_raw(pub,m4[3:],b'LKP1-SIG-SERVER\0'+sha(b''.join(self.messages)))
        self.messages.append(m4)
        if len(m5)!=35 or not hmac.compare_digest(m5[3:],hm(self.s_fin_key,sha(b''.join(self.messages)))):
            raise ProtocolError('server finished')
        self.messages.append(m5)
        m6=message(CERT,cert_body(self.identity.chain)); self.messages.append(m6)
        m7=message(CV,sign_raw(self.identity.private,b'LKP1-SIG-CLIENT\0'+sha(b''.join(self.messages))))
        self.messages.append(m7)
        m8=message(FIN,hm(self.c_fin_key,sha(b''.join(self.messages))))
        self.messages.append(m8)
        out=seal(self.c_hs_key,self.c_hs_iv,0,HANDSHAKE_ENC,m6+m7+m8)
        self._app_keys(); return out


class Server(_Peer):
    def receive_f1(self,record):
        self._deadline()
        if self.state!='IDLE': raise ProtocolError('server state')
        (m1,)=split_messages(unframe(record,HANDSHAKE),(CH,))
        if len(m1)!=69 or m1[3:5]!=b'\0\1': raise ProtocolError('client hello')
        self.messages=[m1]
        from cryptography.hazmat.primitives import serialization
        pub=self.ephemeral.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        m2=message(SH,b'\0\1'+pub+self.random_nonce); self.messages.append(m2)
        self._keys(m1[5:37],m1[37:69],self.random_nonce)
        m3=message(CERT,cert_body(self.identity.chain)); self.messages.append(m3)
        m4=message(CV,sign_raw(self.identity.private,b'LKP1-SIG-SERVER\0'+sha(b''.join(self.messages))))
        self.messages.append(m4)
        m5=message(FIN,hm(self.s_fin_key,sha(b''.join(self.messages))))
        self.messages.append(m5); self.state='SENT_F2'
        return frame(HANDSHAKE,m2),seal(self.s_hs_key,self.s_hs_iv,0,HANDSHAKE_ENC,m3+m4+m5)
    def receive_f3(self,record):
        self._deadline()
        if self.state!='SENT_F2': raise ProtocolError('server state')
        plain=open_sealed(self.c_hs_key,self.c_hs_iv,0,record,HANDSHAKE_ENC)
        m6,m7,m8=split_messages(plain,(CERT,CV,FIN)); self.messages.append(m6)
        pub=self.roots.verify(parse_certs(m6[3:]),PHONE,self.now,False)
        if len(m7)!=67: raise ProtocolError('client signature length')
        verify_raw(pub,m7[3:],b'LKP1-SIG-CLIENT\0'+sha(b''.join(self.messages)))
        self.messages.append(m7)
        if len(m8)!=35 or not hmac.compare_digest(m8[3:],hm(self.c_fin_key,sha(b''.join(self.messages)))):
            raise ProtocolError('client finished')
        self.messages.append(m8); self._app_keys()
        return parse_certs(m6[3:])[0].subject_id
