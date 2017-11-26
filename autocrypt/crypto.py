# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""PGPyCrypto implements the OpenPGP operations needed for Autocrypt.
The API is the same as in bingpg.py.
"""

from __future__ import print_function, unicode_literals

from base64 import b64encode, b64decode
import glob
import os
import logging
import logging.config
import re
import sys
import six

from pgpy import PGPUID, PGPKey, PGPMessage, PGPKeyring, PGPSignature
from pgpy.types import Armorable
from pgpy.packet import Packet
from pgpy.constants import (CompressionAlgorithm, HashAlgorithm, KeyFlags,
                            PubKeyAlgorithm, SymmetricKeyAlgorithm)

# TODO: these two functions should be in a separate file
from .keyinfo import KeyInfo
from .conflog import LOGGING
from .constants import KEY_SIZE, ACCOUNTS, PEERS, SECKEY, PUBKEY

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('autocrypt')


# TODO: see which defaults we would like here
SKEY_ARGS = {
    'hashes': [HashAlgorithm.SHA512, HashAlgorithm.SHA256],
    'ciphers': [SymmetricKeyAlgorithm.AES256,
                SymmetricKeyAlgorithm.AES192,
                SymmetricKeyAlgorithm.AES128],
    'compression': [CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZ2,
                    CompressionAlgorithm.ZIP,
                    CompressionAlgorithm.Uncompressed]
}
# RSAEncrypt is deprecated, therefore using RSAEncryptOrSign
# also for the subkey
SKEY_ALG = PubKeyAlgorithm.RSAEncryptOrSign
SKEY_USAGE_SIGN = {KeyFlags.Sign}
SKEY_USAGE_ENC = {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}
SKEY_USAGE_ALL = {KeyFlags.Sign, KeyFlags.EncryptCommunications,
                  KeyFlags.EncryptStorage}


def key_bytes(pgpykey):
    """Key bytes.

    :param key: key (either public or private)
    :type key: PGPKey
    :return: key bytes
    :rtype: string

    """
    assert isinstance(key, PGPKey)
    return bytes(key) if sys.version_info >= (3, 0) \
        else key.__bytes__()


def _gen_skey_usage_all(addr):
    seckey = PGPKey.new(SKEY_ALG, KEY_SIZE)
    # NOTE: pgpy implements separate attributes for name and e-mail
    # address. Name is mandatory.
    # Here e-mail address is used for the attribute name,
    # so that the uid is 'e-mail adress'.
    # If name attribute would be set to empty string
    # and email to the e-mail address, the uid would be
    # ' <e-mail address>', which we do not want.
    uid = PGPUID.new(addr)
    seckey.add_uid(uid, usage=SKEY_USAGE_ALL, **SKEY_ARGS)
    return seckey


def _gen_ssubkey():
    # NOTE: the uid for the subkeys can be obtained with .parent,
    # but, unlike keys generated with gpg, it's not printed when imported
    # in gpg keyring and run --fingerprint.
    # in case of adding uid to the subkey, it raises currently some
    # exceptions depending on which are the arguments used, which are not
    # clear from the documentation.
    ssubkey = PGPKey.new(SKEY_ALG, KEY_SIZE)
    return ssubkey


def _gen_skey_with_subkey(addr):
    # NOTE: seckey should be generated with usage sign, but otherwise
    # encryption does not work currently.
    seckey = _gen_skey_usage_all(addr)
    ssubkey = _gen_ssubkey()
    seckey.add_subkey(ssubkey, usage=SKEY_USAGE_ENC)
    return seckey


def gen_key(addr):
    return _gen_skey_with_subkey(addr)


def _key2keydata(key):
    assert isinstance(key, PGPKey)
    keybytes = bytes(key)
    kb64bytes = b64encode(keybytes)
    kb64str = kb64bytes.decode('ascii')
    return kb64str


def _keydata2key(keydata):
    assert isinstance(keydata, str)
    kb64bytes = keydata.encode('ascii')
    kbytes = b64decode(kb64bytes)
    key = PGPKey.from_blob(kbytes)
    return key


def _key2keydatas(key):
    assert key is not None
    if key.is_private:
        return (_key2keydata(key), _key2keydata(key.pubkey))
    else:
        return(None, _key2keydata(key))


def _key_path(pgpydir, key):
    ext = '.asc' if key.is_public else '.sec.asc'
    keypath = os.path.join(pgpydir, key.fingerprint.keyid + ext)
    return keypath


def _save_key_to_file(key):
    keypath = _key_path(key)
    with open(keypath, 'wb') as fd:
        fd.write(key_bytes(key))
    return keypath


def list_packets_pgpy(keydata):
    if isinstance(keydata, bytes):
        data = bytearray(keydata)
    elif isinstance(keydata, str):
        data = Armorable.ascii_unarmor(keydata)['body']
    packets = []
    while data:
        packets.append(Packet(data))
    return packets


def _encrypt_with_key(data, key):
    msg = PGPMessage.new(data)
    pubkey = key if key.is_public else key.pubkey
    cmsg = pubkey.encrypt(msg)
    return cmsg

##############################################################################
# from here functions that need profile


def _get_keydata_from_addr(profile, addr):
    if profile[ACCOUNTS].get(addr):
        return profile[ACCOUNTS][addr][SECKEY]
    if profile[PEERS].get(addr):
        return profile[PEERS][addr][PUBKEY]
    return None


def _get_key_from_addr(profile, addr):
    keydata = _get_keydata_from_addr(profile, addr)
    return _keydata2key(keydata) if keydata is not None else None


def get_keydata(profile, addr):
    return _get_keydata_from_addr(profile, addr)

##############################################################################


def _get_keyhandle_from_addr(profile, addr):
    key = _get_key_from_addr(profile, addr)
    return key.fingerprint.keyid


def encrypt(profile, data, recipients):
    assert len(recipients) >= 1
    msg = data if isinstance(data, PGPMessage) else PGPMessage.new(data)
    # pmsg |= seckey.sign(msg)
    if len(recipients) == 1:
        key = _get_key_from_addr(profile, recipients[0])
        pubkey = key if key.is_public else key.pubkey
        cmsg = pubkey.encrypt(msg)
    else:
        # The symmetric cipher should be specified, in case the first
        # preferred cipher is not the same for all recipients public
        # keys.
        cipher = SymmetricKeyAlgorithm.AES256
        sessionkey = cipher.gen_key()
        cmsg = msg
        for r in recipients:
            key = _get_key_from_addr(r)
            pubkey = key if key.is_public else key.pubkey
            cmsg = pubkey.encrypt(cmsg, cipher=cipher,
                                  sessionkey=sessionkey)
        del sessionkey
    assert cmsg.is_encrypted
    return cmsg


def sign(profile, data, addr):
    key = _get_key_from_addr(profile, addr)
    sig_data = key.sign(data)
    return sig_data


def sign_encrypt(profile, data, addr, recipients):
    pmsg = PGPMessage.new(data)
    sig = sign(profile, pmsg, addr)
    pmsg |= sig
    assert pmsg.is_signed
    cmsg = encrypt(pmsg, recipients)
    return cmsg


# def verify(profile, data, signature):
#     sig = PGPSignature(signature) \
#         if isinstance(signature, str) else signature
#     keyhandle = sig.signer.email
#     key = _get_key_from_keyhandle(keyhandle)
#     seckey = key if key.is_public is False else key.pubkey
#     ver = seckey.verify(data, signature)
#     good = next(ver.good_signatures)
#     return good.by


def decrypt(profile, cdata, seckey=None):
    cmsg = cdata if isinstance(cdata, PGPMessage) \
        else PGPMessage.from_blob(cdata)
    assert cmsg.is_encrypted
    if seckey is None:
        addr = cmsg.encrypters.pop().email
        seckey = _get_key_from_addr(profile, addr)
    out = seckey.decrypt(cmsg)
    return out.message


def sym_encrypt(text, passphrase):
    if isinstance(text, str):
        text = PGPMessage.new(text)
    cmsg = text.encrypt(passphrase, cipher=SymmetricKeyAlgorithm.AES128)
    return cmsg


def sym_decrypt(text, passphrase):
    if isinstance(text, str):
        text = PGPMessage.from_blob(text)
    pmsg = text.decrypt(passphrase)
    return pmsg
