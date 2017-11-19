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
                                   gen_headervaluestr_from_headervaluedict, header_unwrap,
                                   header_wrap, gen_ac_headerdict,
                                   gen_ac_headervaluestr, parse_header_value,
                                   parse_ac_headers,
                                   gen_encrypted_email,
                                   add_headers, add_ac_headers,
                                   gen_ac_email, decrypt_email,
                                   parse_ac_email,
                                   header_unwrap_keydata,
                                   gen_gossip_headervalue,
                                   gen_gossip_headervalues,
                                   parse_gossip_list_from_msg,
                                   store_keys_from_gossiplist, get_seckey_from_msg,
                                   parse_gossip_email,
                                   gen_gossip_pt_email,
                                   gen_gossip_email,
                                   gen_ac_setup_ct,
                                   gen_ac_setup_passphrase,
                                   gen_ac_setup_payload,
                                   gen_ac_setup_email, parse_ac_setup_payload,
                                   parse_ac_setup_ct,
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


def test_gen_ac_headervaluestr():
    h = gen_ac_headervaluestr(ALICE, ALICE_KEYDATA, MUTUAL)
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
    msg, pt = parse_ac_email(text, pgpycrypto)
    # NOTE: the following is needed cause decrypt returns pt to have
    # same API as bingpg
    assert parser.parsestr(pt).get_payload() == BODY_AC


def test_gen_gossip_headervalue():
    h = gen_gossip_headervalue(BOB, BOB_KEYDATA)
    assert h == header_unwrap(BOB_GOSSIP)


def test_parse_gossip_list_from_msg(pgpycrypto, datadir):
    text = datadir.read('example-gossip-cleartext_pyac.eml')
    gossip_list = parse_gossip_list_from_msg(text)
    headers = gen_gossip_headervalues(RECIPIENTS, pgpycrypto)
    assert headers == gossip_list


def test_gen_gossip_pt_email(pgpycrypto, datadir):
    text = datadir.read('example-gossip-cleartext_pyac.eml')
    msg = gen_gossip_pt_email(RECIPIENTS, BODY_GOSSIP, pgpycrypto)
    assert msg.as_string() == CLEARTEXT_GOSSIP


def test_gen_gossip_email(pgpycrypto, datadir):
    msg = gen_gossip_email(ALICE, RECIPIENTS, pgpycrypto,
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


def test_parse_gossip_email(pgpycrypto, datadir):
    text = datadir.read('example-gossip_pyac.eml')
    msg, pmsg, gossip = parse_gossip_email(text, pgpycrypto)
    assert pmsg.as_string() == \
        datadir.read('example-gossip-cleartext_pyac.eml').rstrip()


def test_gen_parse_gossip_email(pgpycrypto, datadir):
    msg = gen_gossip_email(ALICE, RECIPIENTS, pgpycrypto,
                              SUBJECT_GOSSIP, BODY_GOSSIP, MUTUAL,
                              '71DBC5657FDE65A7',
                              'Tue, 07 Nov 2017 14:56:25 +0100',
                              True,
                              '<gossip-example@autocrypt.example>',
                              'PLdq3hBodDceBdiavo4rbQeh0u8JfdUHL')

    msg, pmsg, gossip = parse_gossip_email(msg.as_string(),
                                                 pgpycrypto)
    assert pmsg.as_string() + '\n' == \
        datadir.read('example-gossip-cleartext_pyac.eml')


def test_gen_ac_setup_ct(pgpycrypto, datadir):
    ac_setup_ct = gen_ac_setup_ct(ALICE, MUTUAL, pgpycrypto,
                                          '71DBC5657FDE65A7')
    assert ac_setup_ct.split('\n')[:4] == \
        datadir.read('example-setup-message-cleartext-pyac.key').split('\n')[:4]


def test_gen_ac_passphrase():
    passphrase = gen_ac_setup_passphrase()
    assert len(passphrase.split('\n')) == AC_PASSPHRASE_NUM_BLOCKS
    assert len(passphrase.split('-')) == AC_PASSPHRASE_NUM_WORDS
    assert len(passphrase) == AC_PASSPHRASE_LEN + AC_PASSPHRASE_NUM_WORDS - 1 \
        + AC_PASSPHRASE_NUM_BLOCKS - 1
    exp = r'^((\d{4}-){3}\\n){2}(\d{4}-){2}\d{4}$'


def test_gen_ac_setup_payload(pgpycrypto, datadir):
    ac_setup_ct = datadir.read('example-setup-message-cleartext-pyac.key')
    ac_setup_payload = gen_ac_setup_payload(ac_setup_ct, PASSPHRASE,
                                                  pgpycrypto)
    assert ac_setup_payload.split('\n')[:10] == \
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
    ct = parse_ac_setup_payload(AC_SETUP_PAYLOAD)
    assert AC_SETUP_ENC == ct + '\n'


def test_parse_ac_setup_ct(pgpycrypto, datadir):
    pmsg = parse_ac_setup_ct(AC_SETUP_ENC, PASSPHRASE, pgpycrypto)
    # NOTE: this is needed because the blob was not originally encrypted
    # with PGPy. It'll fail with other PGPy versions
    pt = pmsg.message
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    ptlist = pt.split('\n')
    ptlist.insert(1, 'Version: PGPy v0.4.3')
    pt = "\n".join(ptlist)
    assert pt == \
        datadir.read('example-setup-message-cleartext-pyac.key').rstrip('\n')


def test_parse_ac_setup_email(pgpycrypto, datadir):
    ct = datadir.read('example-setup-message-pyac.eml')
    pmsg = parse_ac_setup_email(ct, pgpycrypto, PASSPHRASE)
    # NOTE: this is needed because the blob was not originally encrypted
    # with PGPy. It'll fail with other PGPy versions
    pt = pmsg.message
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    ptlist = pt.split('\n')
    ptlist.insert(1, 'Version: PGPy v0.4.3')
    pt = "\n".join(ptlist)
    assert pt == \
        datadir.read('example-setup-message-cleartext-pyac.key').rstrip('\n')


def test_parse_email(pgpycrypto, datadir):
    ct = datadir.read('example-setup-message-pyac.eml')
    pmsg = parse_email(ct, pgpycrypto, PASSPHRASE)
    # NOTE: this is needed because the blob was not originally encrypted
    # with PGPy. It'll fail with other PGPy versions
    pt = pmsg.message
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    ptlist = pt.split('\n')
    ptlist.insert(1, 'Version: PGPy v0.4.3')
    pt = "\n".join(ptlist)
    assert pt == \
        datadir.read('example-setup-message-cleartext-pyac.key').rstrip('\n')

    text = datadir.read('example-gossip_pyac.eml')
    msg, pmsg, gossip = parse_email(text, pgpycrypto)
    assert pmsg.as_string() == \
        datadir.read('example-gossip-cleartext_pyac.eml').rstrip()

    text = datadir.read('example-simple-autocrypt-pyac.eml')
    msg, pt = parse_ac_email(text, pgpycrypto)
    # NOTE: the following is needed cause decrypt returns pt to have
    # same API as bingpg
    assert parser.parsestr(pt).get_payload() == BODY_AC
