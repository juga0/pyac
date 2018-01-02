# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""Tests for PGPyCrypto."""

from __future__ import unicode_literals

import logging

from autocrypt.conflog import LOGGING
from autocrypt.constants import ACCOUNTS, MUTUAL, PREFERENCRYPT, PUBKEY, SECKEY
from autocrypt.crypto import (_key2keydatas, decrypt, encrypt,
                              sym_decrypt, sym_encrypt, gen_key)
from autocrypt.storage import save
from autocrypt.tests_data import AC_SETUP_ENC, PASSPHRASE

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('autocrypt')


def test_encrypt_decrypt_roundtrip(profile):
    addr = "test@autocrypt.example"
    seckey = gen_key(addr)
    sk, pk = _key2keydatas(seckey)

    profile[ACCOUNTS][addr] = {
        SECKEY: sk,
        PUBKEY: pk,
        PREFERENCRYPT: MUTUAL
    }
    save(profile)

    cmsg = encrypt(profile, "123", [addr])
    pmsg = decrypt(profile, cmsg, seckey)
    assert pmsg == "123"


# def test_gen_key_and_sign_verify(profile):
#     new_account(profile, "hello@xyz.org")
#     sig = sign(profile, "123", "hello@xyz.org")
#     keyhandle_verified = verify(profile, '123', sig)


def test_sym_decrypt(datadir):
    pmsg = sym_decrypt(AC_SETUP_ENC, PASSPHRASE)
    pt = pmsg.message
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    assert pt == \
        datadir.read(
            'example-setup-message-cleartext-pyac.key').rstrip('\n')


def test_sym_encrypt_decrypt(datadir):
    pt = datadir.read('example-setup-message-cleartext-pyac.key')
    cmsg = sym_encrypt(pt, PASSPHRASE)
    pmsg = sym_decrypt(str(cmsg), PASSPHRASE)

    assert pmsg.message == pt
