import json
import sys
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec, x25519

sys.path.insert(0,str(Path(__file__).parents[1]))
from lkp1.cert import Certificate, Identity, RootStore
from lkp1.protocol import Client, Server, ProtocolError, parse_certs, unframe, APP_DATA
from lkp1.provisioning import export_header

V=json.loads(Path(__file__).with_name('vectors.json').read_text())
I=V['inputs']; R=V['records']; M=V['messages']; S=V['secrets']
dec=bytes.fromhex


def peers():
    roots=RootStore(tuple(map(dec,I['roots'])))
    ci=Identity(ec.derive_private_key(int(I['client_private'],16),ec.SECP256R1()),
        tuple(Certificate.decode(dec(x)) for x in I['client_chain']))
    si=Identity(ec.derive_private_key(int(I['server_private'],16),ec.SECP256R1()),
        tuple(Certificate.decode(dec(x)) for x in I['server_chain']))
    c=Client(ci,roots,x25519.X25519PrivateKey.from_private_bytes(dec(I['client_ephemeral_private'])),dec(I['client_nonce']),now=0)
    s=Server(si,roots,x25519.X25519PrivateKey.from_private_bytes(dec(I['server_ephemeral_private'])),dec(I['server_nonce']),now=0)
    return c,s


class ProtocolTests(unittest.TestCase):
    def test_firmware_header_acl(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            lock=path/'lock.json'; phone=path/'phone.json'; output=path/'factory.h'
            lock.write_text(json.dumps({'kind':'lock','private':I['server_private'],
                'chain':I['server_chain'],'roots':I['roots']}))
            phone.write_text(json.dumps({'kind':'phone','subject_id':I['client_id'],
                'chain':I['client_chain']}))
            export_header(lock,output)
            self.assertIn('lkp1_factory_allowed_count = 0u',output.read_text())
            output.unlink()
            export_header(lock,output,[phone])
            self.assertIn('lkp1_factory_allowed_count = 1u',output.read_text())
            output.unlink()
            bad_lock=json.loads(lock.read_text()); bad_lock['private']=I['client_private']
            lock.write_text(json.dumps(bad_lock))
            with self.assertRaises(ValueError): export_header(lock,output)
            bad_lock['private']=I['server_private']; lock.write_text(json.dumps(bad_lock))
            with self.assertRaises(ValueError): export_header(lock,output,[phone,phone])
            bad=json.loads(phone.read_text()); bad['subject_id']='00'*16
            phone.write_text(json.dumps(bad))
            with self.assertRaises(ValueError): export_header(lock,output,[phone])

    def test_fixture_interop(self):
        c,s=peers(); self.assertEqual(c.start(),dec(R['F1']))
        a,b=s.receive_f1(dec(R['F1'])); self.assertEqual(a,dec(R['F2a']))
        # Encrypted bytes vary with a freshly randomized ECDSA signature.
        f3=c.receive_f2(dec(R['F2a']),dec(R['F2b']),dec(I['server_id']))
        self.assertEqual(c.messages[:5],[dec(M[f'M{i}']) for i in range(1,6)])
        # Server accepts fixture F3, whose client signature was recorded once.
        s.messages[2:5]=[dec(M[f'M{i}']) for i in range(3,6)]
        self.assertEqual(s.receive_f3(dec(R['F3'])),dec(I['client_id']))
        self.assertEqual(s.master,dec(S['master']))
        self.assertEqual(s.recv_app(dec(R['app0'])),dec(V['app0_plaintext']))

    def test_bad_record_and_suite(self):
        c,s=peers(); c.start()
        with self.assertRaises(ProtocolError): s.receive_f1(dec(R['F1'])[:-1])
        c,s=peers(); broken=bytearray(dec(R['F1'])); broken[7]=2
        with self.assertRaises(ProtocolError): s.receive_f1(bytes(broken))
        with self.assertRaises(ProtocolError): unframe(b'\x01\x03\x04\x01',APP_DATA)

    def test_cert_validation(self):
        c,s=peers(); cert=s.identity.chain[0]
        with self.assertRaises(ValueError): c.roots.verify((cert,),2,now=0)
        damaged=bytearray(cert.encode()); damaged[-1]^=1
        with self.assertRaises(ValueError): c.roots.verify((Certificate.decode(damaged),),1,now=0)
        with self.assertRaises(ValueError): RootStore((bytes(64),)).verify((cert,),1,now=0)

    def test_replay_sequence_tag_and_order(self):
        c,s=peers(); c.start(); s.receive_f1(dec(R['F1']))
        with self.assertRaises(ProtocolError): s.receive_f1(dec(R['F1']))
        s.messages[2:5]=[dec(M[f'M{i}']) for i in range(3,6)]
        s.receive_f3(dec(R['F3']))
        self.assertEqual(s.recv_app(dec(R['app0'])),dec(V['app0_plaintext']))
        with self.assertRaises(ProtocolError): s.recv_app(dec(R['app0']))
        c,s=peers(); c.start(); s.receive_f1(dec(R['F1'])); s.messages[2:5]=[dec(M[f'M{i}']) for i in range(3,6)]; s.receive_f3(dec(R['F3']))
        damaged=bytearray(dec(R['app0'])); damaged[-1]^=1
        with self.assertRaises(Exception): s.recv_app(bytes(damaged))

    def test_low_order(self):
        c,s=peers(); raw=bytearray(dec(R['F1'])); raw[9:41]=bytes(32)
        with self.assertRaises(Exception): s.receive_f1(bytes(raw))

    def test_transcript_reflection_and_truncation(self):
        c,s=peers(); c.start()
        with self.assertRaises(ProtocolError): c.receive_f2(dec(R['F1']),dec(R['F2b']),dec(I['server_id']))
        c,s=peers(); c.start()
        bad=bytearray(dec(R['F2a'])); bad[-1]^=1
        with self.assertRaises(Exception): c.receive_f2(bytes(bad),dec(R['F2b']),dec(I['server_id']))
        c,s=peers(); c.start()
        with self.assertRaises(ProtocolError): c.receive_f2(dec(R['F2a']),dec(R['F2b'])[:-1],dec(I['server_id']))

    def test_wrong_usage_and_issuer(self):
        c,s=peers(); original=s.identity.chain[0]
        forged=Certificate(original.kind,original.subject_id,original.issuer_key_id,
            original.not_before,original.not_after,0,original.subject_pub,original.signature)
        with self.assertRaises(ValueError): c.roots.verify((forged,),1,now=0)
        forged=Certificate(original.kind,original.subject_id,bytes(8),
            original.not_before,original.not_after,original.usage,original.subject_pub,original.signature)
        with self.assertRaises(ValueError): c.roots.verify((forged,),1,now=0)


if __name__=='__main__': unittest.main()
