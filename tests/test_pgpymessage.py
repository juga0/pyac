# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""Functions to test pgpymessage."""

from __future__ import unicode_literals
import logging
from email.parser import Parser
from email import policy

from autocrypt.conflog import LOGGING
from autocrypt.examples_data import (ALICE, BOB, RECIPIENTS, ALICE_KEYDATA,
                                     BOB_KEYDATA, BOB_GOSSIP, ALICE_AC,
                                     SUBJECT_GOSSIP, BODY_GOSSIP,
                                     BOB_KEYDATA_WRAPPED, CLEARTEXT_GOSSIP,
                                     PASSPHRASE, AC_SETUP_PAYLOAD,
                                     AC_SETUP_ENC, PGPHOME, SUBJECT_AC,
                                     BODY_AC)

from autocrypt.constants import (MUTUAL, AC_PASSPHRASE_NUM_BLOCKS,
                                 AC_PASSPHRASE_NUM_WORDS, AC_PASSPHRASE_LEN,
                                 AC_SETUP_SUBJECT)

# from autocrypt.pgpycrypto import PGPyCrypto

from autocrypt.pgpymessage import (wrap, unwrap,
                                   gen_header_from_dict, header_unwrap,
                                   header_wrap, gen_ac_headervaluedict,
                                   gen_ac_header, parse_header_value,
                                   parse_ac_headers,
                                   gen_mime_enc_multipart,
                                   gen_headers, gen_ac_headers,
                                   gen_ac_email, decrypt_mime_enc_email,
                                   parse_ac_email,
                                   ac_header_email_unwrap_keydata,
                                   gen_ac_gossip_header,
                                   gen_ac_gossip_headers,
                                   parse_ac_gossip_headers,
                                   store_gossip_keys, get_skey_from_msg,
                                   parse_ac_gossip_email,
                                   gen_ac_gossip_cleartext_email,
                                   gen_ac_gossip_email,
                                   gen_ac_setup_seckey,
                                   gen_ac_setup_passphrase,
                                   gen_ac_setup_enc_seckey,
                                   gen_ac_setup_email, parse_ac_setup_payload,
                                   parse_ac_setup_enc_part,
                                   parse_ac_setup_email, parse_email)

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('autocrypt')
logger.setLevel(logging.DEBUG)
parser = Parser(policy=policy.default)
# pgpycrypto = PGPyCrypto(PGPHOME)


def test_wrap():
    wrappedstr = wrap(BOB_KEYDATA, wrapstr='\n ')
    assert wrappedstr == BOB_KEYDATA_WRAPPED


def test_ac_header_wrap():
    pass


def test_gen_ac_header():
    h = gen_ac_header(ALICE, ALICE_KEYDATA, MUTUAL)
    assert h == header_unwrap(ALICE_AC)


def test_gen_ac_email(pgpycrypto, datadir):
    msg = gen_ac_email(ALICE, [BOB], pgpycrypto, SUBJECT_AC, BODY_AC, MUTUAL,
                       date='Tue, 07 Nov 2017 14:53:50 +0100',
                       _dto='<bob@autocrypt.example>',
                       message_id='<rsa-3072@autocrypt.example>',
                       boundary='Y6fyGi9SoGeH8WwRaEdC6bbBcYOedDzrQ')
    text = datadir.read('example-simple-autocrypt-pyac.eml')
    assert msg.as_string().split('\n')[:23] == \
        text.split('\n')[:23]


def test_parse_ac_email(pgpycrypto, datadir):
    text = datadir.read('example-simple-autocrypt-pyac.eml')
    msg, dec = parse_ac_email(text, pgpycrypto)
    # NOTE: the following is needed cause decrypt returns plaintext to have
    # same API as bingpg
    assert parser.parsestr(dec).get_payload() == BODY_AC


def test_gen_ac_gossip_header():
    h = gen_ac_gossip_header(BOB, BOB_KEYDATA)
    assert h == header_unwrap(BOB_GOSSIP)


def test_parse_ac_gossip_header(pgpycrypto, datadir):
    text = datadir.read('example-gossip-cleartext_pyac.eml')
    gossip_list = parse_ac_gossip_headers(text)
    headers = gen_ac_gossip_headers(RECIPIENTS, pgpycrypto)
    assert headers == gossip_list


def test_gen_ac_gossip_cleartext_email(pgpycrypto, datadir):
    text = datadir.read('example-gossip-cleartext_pyac.eml')
    msg = gen_ac_gossip_cleartext_email(RECIPIENTS, BODY_GOSSIP, pgpycrypto)
    assert msg.as_string() == CLEARTEXT_GOSSIP


def test_gen_ac_gossip_email(pgpycrypto, datadir):
    msg = gen_ac_gossip_email(ALICE, RECIPIENTS, pgpycrypto,
                              SUBJECT_GOSSIP, BODY_GOSSIP, MUTUAL,
                              '71DBC5657FDE65A7',
                              'Tue, 07 Nov 2017 14:56:25 +0100',
                              True,
                              '<gossip-example@autocrypt.example>',
                              'PLdq3hBodDceBdiavo4rbQeh0u8JfdUHL')
    # NOTE: taking only first 25 lines as the encrypted blob is different
    # every time
    assert msg.as_string().split()[:25] == \
        datadir.read('example-gossip_pyac.eml').split()[:25]


def test_parse_ac_gossip_email(pgpycrypto, datadir):
    text = datadir.read('example-gossip_pyac.eml')
    msg, dec_msg, gossip = parse_ac_gossip_email(text, pgpycrypto)
    assert dec_msg.as_string() == \
        datadir.read('example-gossip-cleartext_pyac.eml').rstrip()


def test_gen_parse_ac_gossip_email(pgpycrypto, datadir):
    msg = gen_ac_gossip_email(ALICE, RECIPIENTS, pgpycrypto,
                              SUBJECT_GOSSIP, BODY_GOSSIP, MUTUAL,
                              '71DBC5657FDE65A7',
                              'Tue, 07 Nov 2017 14:56:25 +0100',
                              True,
                              '<gossip-example@autocrypt.example>',
                              'PLdq3hBodDceBdiavo4rbQeh0u8JfdUHL')

    msg, dec_msg, gossip = parse_ac_gossip_email(msg.as_string(),
                                                 pgpycrypto)
    assert dec_msg.as_string() + '\n' == \
        datadir.read('example-gossip-cleartext_pyac.eml')


def test_gen_ac_setup_seckey(pgpycrypto, datadir):
    ac_setup_seckey = gen_ac_setup_seckey(ALICE, MUTUAL, pgpycrypto,
                                          '71DBC5657FDE65A7')
    assert ac_setup_seckey.split('\n')[:4] == \
        datadir.read('example-setup-message-cleartext-pyac.key').split('\n')[:4]


def test_gen_ac_passphrase():
    passphrase = gen_ac_setup_passphrase()
    assert len(passphrase.split('\n')) == AC_PASSPHRASE_NUM_BLOCKS
    assert len(passphrase.split('-')) == AC_PASSPHRASE_NUM_WORDS
    assert len(passphrase) == AC_PASSPHRASE_LEN + AC_PASSPHRASE_NUM_WORDS - 1 \
        + AC_PASSPHRASE_NUM_BLOCKS - 1
    exp = r'^((\d{4}-){3}\\n){2}(\d{4}-){2}\d{4}$'


def test_gen_ac_setup_enc_seckey(pgpycrypto, datadir):
    ac_setup_seckey = datadir.read('example-setup-message-cleartext-pyac.key')
    ac_setup_enc_seckey = gen_ac_setup_enc_seckey(ac_setup_seckey, PASSPHRASE,
                                                  pgpycrypto)
    assert ac_setup_enc_seckey.split('\n')[:10] == \
        AC_SETUP_PAYLOAD.split('\n')[:10]


def test_gen_ac_setup_email(pgpycrypto, datadir):
    ac_setup_email = gen_ac_setup_email(ALICE, MUTUAL, pgpycrypto,
                                        date="Sun, 05 Nov 2017 08:44:38 GMT",
                                        keyhandle='71DBC5657FDE65A7',
                                        boundary='Y6fyGi9SoGeH8WwRaEdC6bbBcYOedDzrQ',
                                        passphrase=PASSPHRASE)
    with open('foo', 'w') as f:
        f.write(ac_setup_email.as_string())
    assert ac_setup_email.as_string().split('\n')[:33] == \
        datadir.read('example-setup-message-pyac.eml').split('\n')[:33]


def test_parse_ac_setup_payload(pgpycrypto):
    enctext = parse_ac_setup_payload(AC_SETUP_PAYLOAD)
    assert AC_SETUP_ENC == enctext + '\n'


def test_parse_ac_setup_enc_part(pgpycrypto, datadir):
    plainmsg = parse_ac_setup_enc_part(AC_SETUP_ENC, PASSPHRASE, pgpycrypto)
    # NOTE: this is needed because the blob was not originally encrypted
    # with PGPy. It'll fail with other PGPy versions
    pt = plainmsg.message
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    ptlist = pt.split('\n')
    ptlist.insert(1, 'Version: PGPy v0.4.3')
    pt = "\n".join(ptlist)
    plaintext = datadir.read('example-setup-message-cleartext-pyac.key')
    assert pt == plaintext.rstrip('\n')


def test_parse_ac_setup_email(pgpycrypto, datadir):
    enctext = datadir.read('example-setup-message-pyac.eml')
    plainmsg = parse_ac_setup_email(enctext, pgpycrypto, PASSPHRASE)
    # NOTE: this is needed because the blob was not originally encrypted
    # with PGPy. It'll fail with other PGPy versions
    pt = plainmsg.message
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    ptlist = pt.split('\n')
    ptlist.insert(1, 'Version: PGPy v0.4.3')
    pt = "\n".join(ptlist)
    plaintext = datadir.read('example-setup-message-cleartext-pyac.key')
    assert pt == plaintext.rstrip('\n')


def test_parse_email(pgpycrypto, datadir):
    enctext = datadir.read('example-setup-message-pyac.eml')
    plainmsg = parse_email(enctext, pgpycrypto, PASSPHRASE)
    # NOTE: this is needed because the blob was not originally encrypted
    # with PGPy. It'll fail with other PGPy versions
    pt = plainmsg.message
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    ptlist = pt.split('\n')
    ptlist.insert(1, 'Version: PGPy v0.4.3')
    pt = "\n".join(ptlist)
    plaintext = datadir.read('example-setup-message-cleartext-pyac.key')
    assert pt == plaintext.rstrip('\n')

    text = datadir.read('example-gossip_pyac.eml')
    msg, dec_msg, gossip = parse_email(text, pgpycrypto)
    assert dec_msg.as_string() == \
        datadir.read('example-gossip-cleartext_pyac.eml').rstrip()

    text = datadir.read('example-simple-autocrypt-pyac.eml')
    msg, dec = parse_ac_email(text, pgpycrypto)
    # NOTE: the following is needed cause decrypt returns plaintext to have
    # same API as bingpg
    assert parser.parsestr(dec).get_payload() == BODY_AC
