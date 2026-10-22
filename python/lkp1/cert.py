"""Compact certificate encoding and chain validation."""
from dataclasses import dataclass
import hashlib
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

LOCK, PHONE, ISSUING_CA = 1, 2, 16
SIGN_HANDSHAKE, CA_SIGN = 1, 2


def public_bytes(key):
    n = key.public_numbers()
    return n.x.to_bytes(32, 'big') + n.y.to_bytes(32, 'big')


def load_public(raw):
    if len(raw) != 64:
        raise ValueError('P-256 public key length')
    return ec.EllipticCurvePublicNumbers(int.from_bytes(raw[:32], 'big'),
        int.from_bytes(raw[32:], 'big'), ec.SECP256R1()).public_key()


def key_id(raw):
    return hashlib.sha256(raw).digest()[:8]


def sign_raw(private, data):
    der = private.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def verify_raw(public, signature, data):
    if len(signature) != 64:
        raise ValueError('signature length')
    r, s = int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big')
    try:
        public.verify(utils.encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError('invalid signature') from exc


@dataclass(frozen=True)
class Certificate:
    kind: int
    subject_id: bytes
    issuer_key_id: bytes
    not_before: int
    not_after: int
    usage: int
    subject_pub: bytes
    signature: bytes

    @property
    def tbs(self):
        if len(self.subject_id) != 16 or len(self.issuer_key_id) != 8 or len(self.subject_pub) != 64:
            raise ValueError('certificate field length')
        return (bytes((1, self.kind)) + self.subject_id + self.issuer_key_id +
            self.not_before.to_bytes(4, 'big') + self.not_after.to_bytes(4, 'big') +
            self.usage.to_bytes(2, 'big') + self.subject_pub)

    def encode(self):
        if len(self.signature) != 64:
            raise ValueError('certificate signature length')
        return self.tbs + self.signature

    @classmethod
    def decode(cls, raw):
        raw = bytes(raw)
        if len(raw) != 164 or raw[0] != 1:
            raise ValueError('certificate encoding')
        return cls(raw[1], raw[2:18], raw[18:26], int.from_bytes(raw[26:30], 'big'),
            int.from_bytes(raw[30:34], 'big'), int.from_bytes(raw[34:36], 'big'),
            raw[36:100], raw[100:164])


def issue(issuer_private, kind, subject_id, subject_pub, usage, not_before=0, not_after=0):
    cert = Certificate(kind, subject_id, key_id(public_bytes(issuer_private.public_key())),
        not_before, not_after, usage, subject_pub, bytes(64))
    return Certificate(kind, subject_id, cert.issuer_key_id, not_before, not_after,
        usage, subject_pub, sign_raw(issuer_private, cert.tbs))


@dataclass
class Identity:
    private: ec.EllipticCurvePrivateKey
    chain: tuple[Certificate, ...]


class RootStore:
    def __init__(self, roots):
        if len(roots) > 2:
            raise ValueError('at most two roots')
        self.roots = {key_id(raw): load_public(raw) for raw in roots}

    def verify(self, chain, role, now=None, check_expiry=True, pinned_id=None):
        if not 1 <= len(chain) <= 2:
            raise ValueError('certificate chain length')
        leaf = chain[0]
        if leaf.kind != role or leaf.usage & SIGN_HANDSHAKE == 0:
            raise ValueError('certificate role or usage')
        if pinned_id is not None and leaf.subject_id != pinned_id:
            raise ValueError('pinned identity mismatch')
        if len(chain) == 2:
            ca = chain[1]
            if ca.kind != ISSUING_CA or ca.usage & CA_SIGN == 0:
                raise ValueError('issuing CA role or usage')
            root = self.roots.get(ca.issuer_key_id)
            if root is None:
                raise ValueError('untrusted root')
            verify_raw(root, ca.signature, ca.tbs)
            issuer = load_public(ca.subject_pub)
        else:
            issuer = self.roots.get(leaf.issuer_key_id)
            if issuer is None:
                raise ValueError('untrusted root')
        if leaf.issuer_key_id != key_id(public_bytes(issuer)):
            raise ValueError('wrong issuer')
        verify_raw(issuer, leaf.signature, leaf.tbs)
        if check_expiry:
            current = int(time.time()) if now is None else now
            for cert in chain:
                if current < cert.not_before or cert.not_after and current > cert.not_after:
                    raise ValueError('certificate time')
        return load_public(leaf.subject_pub)
