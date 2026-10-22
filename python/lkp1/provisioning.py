"""Offline prototype provisioning CLI. Keep private JSON files secret."""
import argparse
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from .cert import LOCK, PHONE, ISSUING_CA, SIGN_HANDSHAKE, CA_SIGN, Certificate, RootStore, issue, public_bytes, key_id


def private_hex(key): return key.private_numbers().private_value.to_bytes(32,'big').hex()
def load_private(value): return ec.derive_private_key(int(value,16),ec.SECP256R1())
def write(path,data,private=False):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600 if private else 0o644)
    with os.fdopen(fd,'w') as out: json.dump(data,out,indent=2); out.write('\n')


def export_header(source, output, allowed_phones=()):
    """Emit the C identity layout used by nrf52840/include/lkp1/server.h."""
    data=json.loads(Path(source).read_text())
    if data.get('kind')!='lock': raise ValueError('firmware identity must be a lock leaf')
    private=bytes.fromhex(data['private']); chain=[bytes.fromhex(x) for x in data['chain']]
    roots=[bytes.fromhex(x) for x in data['roots']]
    if len(private)!=32 or not 1<=len(chain)<=2 or not 1<=len(roots)<=2 or any(len(c)!=164 for c in chain) or any(len(r)!=64 for r in roots):
        raise ValueError('invalid credential lengths')
    lock_chain=tuple(Certificate.decode(raw) for raw in chain)
    trust=RootStore(roots)
    trust.verify(lock_chain,LOCK,check_expiry=False)
    if public_bytes(load_private(data['private']).public_key()) != lock_chain[0].subject_pub:
        raise ValueError('lock private key does not match certificate')
    if 'subject_id' in data and bytes.fromhex(data['subject_id']) != lock_chain[0].subject_id:
        raise ValueError('lock subject id does not match certificate')
    body=bytes((len(chain),))+b''.join((164).to_bytes(2,'big')+c for c in chain)
    allowed=[]
    for phone_path in allowed_phones:
        if len(allowed) == 8: raise ValueError('at most eight allowed phones')
        phone=json.loads(Path(phone_path).read_text())
        if phone.get('kind')!='phone': raise ValueError('allowed identity must be phone')
        phone_id=bytes.fromhex(phone['subject_id'])
        phone_chain=tuple(Certificate.decode(bytes.fromhex(x)) for x in phone['chain'])
        if len(phone_id)!=16: raise ValueError('allowed phone id length')
        trust.verify(phone_chain,PHONE,check_expiry=False,pinned_id=phone_id)
        if phone_id in allowed: raise ValueError('duplicate allowed phone')
        allowed.append(phone_id)
    def array(raw): return ', '.join(f'0x{x:02x}' for x in raw)
    lines=['/* Generated offline by lkp1.provisioning. Secret: never commit this file. */',
        '#ifndef LKP1_FACTORY_CREDENTIALS_H','#define LKP1_FACTORY_CREDENTIALS_H',
        '#include "lkp1/server.h"', '#define LKP1_FACTORY_PROVISIONED 1',
        f'static const uint8_t lkp1_factory_private_key[32] = {{{array(private)}}};',
        f'static const uint8_t lkp1_factory_cert_body[{len(body)}] = {{{array(body)}}};',
        'static const struct lkp1_root lkp1_factory_roots[] = {']
    for root in roots: lines.append(f'    {{.public_key = {{{array(root)}}}, .key_id = {{{array(key_id(root))}}}}},')
    lines += ['};']
    if allowed:
        lines.append(f'static const uint8_t lkp1_factory_allowed_ids[{len(allowed)}][16] = {{')
        lines += [f'    {{{array(phone_id)}}},' for phone_id in allowed]
        lines.append('};')
    else:
        # Standard C does not permit a zero-length array; count zero is authoritative.
        lines.append('static const uint8_t lkp1_factory_allowed_ids[1][16] = {{0}};')
    lines += [f'static const size_t lkp1_factory_allowed_count = {len(allowed)}u;',
        'static const struct lkp1_server_identity lkp1_factory_identity = {',
        '    lkp1_factory_cert_body, sizeof(lkp1_factory_cert_body),',
        '    lkp1_factory_private_key, lkp1_factory_roots,',
        '    sizeof(lkp1_factory_roots) / sizeof(lkp1_factory_roots[0])',
        '};','#endif']
    path=Path(output); path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as out: out.write('\n'.join(lines)+'\n')


def main(argv=None):
    p=argparse.ArgumentParser(description='LKP1 offline prototype CA provisioning')
    sub=p.add_subparsers(dest='command',required=True)
    root=sub.add_parser('root'); root.add_argument('output')
    ca=sub.add_parser('issuing-ca'); ca.add_argument('root_json'); ca.add_argument('output'); ca.add_argument('--id',required=True,help='16-byte hex')
    leaf=sub.add_parser('leaf'); leaf.add_argument('issuer_json'); leaf.add_argument('output')
    leaf.add_argument('--type',choices=('lock','phone'),required=True)
    leaf.add_argument('--id',required=True,help='16-byte hex serial/device id')
    header=sub.add_parser('firmware-header'); header.add_argument('lock_json'); header.add_argument('output')
    header.add_argument('--allow-phone',action='append',default=[],metavar='PHONE_JSON')
    a=p.parse_args(argv)
    if a.command=='firmware-header': export_header(a.lock_json,a.output,a.allow_phone); return
    if a.command=='root':
        key=ec.generate_private_key(ec.SECP256R1())
        write(a.output,{'kind':'root','private':private_hex(key),'public':public_bytes(key.public_key()).hex()},True)
        return
    issuer_data=json.loads(Path(a.root_json if a.command=='issuing-ca' else a.issuer_json).read_text())
    issuer=load_private(issuer_data['private'])
    ident=bytes.fromhex(a.id)
    if len(ident)!=16: p.error('--id must be 16 bytes')
    key=ec.generate_private_key(ec.SECP256R1())
    if a.command=='issuing-ca':
        if issuer_data['kind']!='root': p.error('issuing CA must be signed by root')
        cert=issue(issuer,ISSUING_CA,ident,public_bytes(key.public_key()),CA_SIGN)
        data={'kind':'issuing-ca','private':private_hex(key),'public':public_bytes(key.public_key()).hex(),
              'chain':[cert.encode().hex()],'roots':[issuer_data['public']]}
    else:
        kind=LOCK if a.type=='lock' else PHONE
        if issuer_data['kind'] not in ('root','issuing-ca'): p.error('invalid issuer')
        cert=issue(issuer,kind,ident,public_bytes(key.public_key()),SIGN_HANDSHAKE)
        data={'kind':a.type,'private':private_hex(key),'public':public_bytes(key.public_key()).hex(),
              'subject_id':ident.hex(),'chain':[cert.encode().hex()]+issuer_data.get('chain',[]),
              'roots':issuer_data.get('roots',[issuer_data['public']])}
    write(a.output,data,True)


if __name__=='__main__': main()
