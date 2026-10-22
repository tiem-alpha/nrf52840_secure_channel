"""Generate the checked-in fixture once; ECDSA signatures are fixed in JSON."""
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from lkp1.cert import LOCK, PHONE, SIGN_HANDSHAKE, Identity, RootStore, issue, public_bytes
from lkp1.protocol import Client, Server, hm, sha, expand

root=ec.derive_private_key(0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234,ec.SECP256R1())
server_key=ec.derive_private_key(0x23456789abcdef123456789abcdef123456789abcdef123456789abcdef12345,ec.SECP256R1())
client_key=ec.derive_private_key(0x3456789abcdef123456789abcdef123456789abcdef123456789abcdef123456,ec.SECP256R1())
server_id=bytes.fromhex('00112233445566778899aabbccddeeff')
client_id=bytes.fromhex('ffeeddccbbaa99887766554433221100')
server_cert=issue(root,LOCK,server_id,public_bytes(server_key.public_key()),SIGN_HANDSHAKE)
client_cert=issue(root,PHONE,client_id,public_bytes(client_key.public_key()),SIGN_HANDSHAKE)
roots=RootStore((public_bytes(root.public_key()),))
c_eph=bytes.fromhex('40'*32); s_eph=bytes.fromhex('50'*32)
c_nonce=bytes(range(32)); s_nonce=bytes(range(32,64))
client=Client(Identity(client_key,(client_cert,)),roots,x25519.X25519PrivateKey.from_private_bytes(c_eph),c_nonce,now=0)
server=Server(Identity(server_key,(server_cert,)),roots,x25519.X25519PrivateKey.from_private_bytes(s_eph),s_nonce,now=0)
f1=client.start(); f2a,f2b=server.receive_f1(f1); f3=client.receive_f2(f2a,f2b,server_id)
pre={k:getattr(client,k) for k in ('master','c2s_key','c2s_iv','s2c_key','s2c_iv','session_id')}
ss=x25519.X25519PrivateKey.from_private_bytes(c_eph).exchange(x25519.X25519PrivateKey.from_private_bytes(s_eph).public_key())
prk=hm(c_nonce+s_nonce,ss); ctx=sha(b''.join(client.messages[:2]))
for name,n in [('c_hs_key',16),('c_hs_iv',12),('s_hs_key',16),('s_hs_iv',12),('c_fin_key',32),('s_fin_key',32)]:
    pre[name]=expand(prk,name.replace('_',' ').replace('fin key','finished'),ctx,n)
server.receive_f3(f3)
app0=client.send_app(b'\x01demo')
assert server.recv_app(app0)==b'\x01demo'
fixture={
 'inputs':{'root_private':root.private_numbers().private_value.to_bytes(32,'big').hex(),
   'server_private':server_key.private_numbers().private_value.to_bytes(32,'big').hex(),
   'client_private':client_key.private_numbers().private_value.to_bytes(32,'big').hex(),
   'server_ephemeral_private':s_eph.hex(),'client_ephemeral_private':c_eph.hex(),
   'server_nonce':s_nonce.hex(),'client_nonce':c_nonce.hex(),
   'server_chain':[server_cert.encode().hex()],'client_chain':[client_cert.encode().hex()],
   'roots':[public_bytes(root.public_key()).hex()], 'server_id':server_id.hex(),'client_id':client_id.hex()},
 'messages':{f'M{i}':m.hex() for i,m in enumerate(client.messages,1)},
 'records':{k:v.hex() for k,v in {'F1':f1,'F2a':f2a,'F2b':f2b,'F3':f3,'app0':app0}.items()},
 'secrets':{k:v.hex() for k,v in pre.items()},'app0_plaintext':b'\x01demo'.hex()}
Path(__file__).with_name('vectors.json').write_text(json.dumps(fixture,indent=2)+'\n')
