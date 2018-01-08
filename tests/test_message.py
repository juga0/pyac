# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""Functions to test pgpymessage."""

from __future__ import unicode_literals

import logging
from email import policy
from email.parser import Parser

from autocrypt.conflog import LOGGING
from autocrypt.constants import (AC_PASSPHRASE_LEN, AC_PASSPHRASE_NUM_BLOCKS,
                                 AC_PASSPHRASE_NUM_WORDS, MUTUAL)
from autocrypt.message import (gen_ac_headervaluestr, gen_ac_setup_ct,
                               gen_ac_setup_email, gen_ac_setup_passphrase,
                               gen_ac_setup_payload, gen_gossip_email,
                               gen_gossip_headervalue, gen_gossip_headervalues,
                               gen_gossip_pt_email, header_unwrap,
                               parse_ac_email, parse_ac_setup_ct,
                               parse_ac_setup_email, parse_ac_setup_payload,
                               parse_email, parse_gossip_email,
                               parse_gossip_list_from_msg, wrap)
from autocrypt.storage import repr_profile
from autocrypt.tests_data import (AC_SETUP_ENC, AC_SETUP_PAYLOAD, ALICE,
                                  ALICE_AC, ALICE_KEYDATA, BOB, BOB_GOSSIP,
                                  BOB_KEYDATA, BOB_KEYDATA_WRAPPED, BODY_AC,
                                  BODY_GOSSIP, CLEARTEXT_GOSSIP, PASSPHRASE,
                                  RECIPIENTS, SUBJECT_GOSSIP)


logging.config.dictConfig(LOGGING)
logger = logging.getLogger('autocrypt')
logger.setLevel(logging.DEBUG)
parser = Parser(policy=policy.default)


def test_wrap():
    wrappedstr = wrap(BOB_KEYDATA, wrapstr='\n ')
    assert wrappedstr == BOB_KEYDATA_WRAPPED


def test_ac_header_wrap():
    pass


def test_gen_ac_headervaluestr():
    h = gen_ac_headervaluestr(ALICE, ALICE_KEYDATA, MUTUAL)
    assert h == header_unwrap(ALICE_AC)


def test_gen_ac_email(profile, datadir):
    pass
    # msg = gen_ac_email(ALICE, [BOB], profile, SUBJECT_AC, BODY_AC, MUTUAL,
    #                    date='Tue, 07 Nov 2017 14:53:50 +0100',
    #                    _dto='<bob@autocrypt.example>',
    #                    message_id='<rsa-3072@autocrypt.example>',
    #                    boundary='Y6fyGi9SoGeH8WwRaEdC6bbBcYOedDzrQ')
    # text = datadir.read('example-simple-autocrypt-pyac.eml')
#     assert msg.as_string().split('\n')[:23] == \
#         text.split('\n')[:23]


def test_parse_ac_email(profile, datadir):
    logger.debug(repr_profile(profile))
    logger.debug(datadir.basepath)
    logger.debug(profile['path'])
    text = datadir.read('example-simple-autocrypt-pyac.eml')
    pt = parse_ac_email(text, profile)
    # NOTE: the following is needed cause decrypt returns pt to have
    # same API as bingpg
    assert parser.parsestr(pt).get_payload() == BODY_AC


def test_gen_gossip_headervalue():
    h = gen_gossip_headervalue(BOB, BOB_KEYDATA)
    assert h == header_unwrap(BOB_GOSSIP)


def test_parse_gossip_list_from_msg(profile, datadir):
    text = datadir.read('example-gossip-cleartext_pyac.eml')
    gossip_list = parse_gossip_list_from_msg(text)
    logger.debug(gossip_list)
    headers = gen_gossip_headervalues(RECIPIENTS, profile)
    logger.debug(headers)
    assert headers == gossip_list


def test_gen_gossip_pt_email(profile, datadir):
    # text = datadir.read('example-gossip-cleartext_pyac.eml')
    msg = gen_gossip_pt_email(RECIPIENTS, BODY_GOSSIP, profile)
    logger.debug(msg.as_string())
    assert msg.as_string() == CLEARTEXT_GOSSIP


def test_gen_gossip_email(profile, datadir):
    msg = gen_gossip_email(ALICE, RECIPIENTS, profile,
                           SUBJECT_GOSSIP, BODY_GOSSIP, MUTUAL,
                           '71DBC5657FDE65A7',
                           'Tue, 07 Nov 2017 14:56:25 +0100',
                           True,
                           '<gossip-example@autocrypt.example>',
                           'PLdq3hBodDceBdiavo4rbQeh0u8JfdUHL')
    # NOTE: taking only first 25 lines as the encrypted blob is different
    # every time
    logger.debug('msg str %s', msg.as_string())
    assert msg.as_string().split()[:25] == \
        datadir.read('example-gossip_pyac.eml').split()[:25]


def test_parse_gossip_email(profile, datadir):
    text = datadir.read('example-gossip_pyac2.eml')
    pt = parse_gossip_email(text, profile)
    logger.debug('pt %s', pt)
    assert pt.rstrip() == \
        datadir.read('example-gossip-cleartext_pyac.eml').rstrip()


def test_gen_parse_gossip_email(profile, datadir):
    msg = gen_gossip_email(ALICE, RECIPIENTS, profile,
                           SUBJECT_GOSSIP, BODY_GOSSIP, MUTUAL,
                           '71DBC5657FDE65A7',
                           'Tue, 07 Nov 2017 14:56:25 +0100',
                           True,
                           '<gossip-example@autocrypt.example>',
                           'PLdq3hBodDceBdiavo4rbQeh0u8JfdUHL')
    pt = parse_gossip_email(msg.as_string(), profile)
    assert pt == \
        datadir.read('example-gossip-cleartext_pyac.eml')


def test_gen_ac_setup_ct(profile, datadir):
    ac_setup_ct = gen_ac_setup_ct(ALICE, MUTUAL, profile,
                                  '71DBC5657FDE65A7')
    logger.debug('ac_setup_ct %s', ac_setup_ct.split('\n')[:4])
    assert ac_setup_ct.split('\n')[:4] == \
        datadir.read(
            'example-setup-message-cleartext-pyac.key').split('\n')[:4]


def test_gen_ac_passphrase():
    passphrase = gen_ac_setup_passphrase()
    assert len(passphrase.split('\n')) == AC_PASSPHRASE_NUM_BLOCKS
    assert len(passphrase.split('-')) == AC_PASSPHRASE_NUM_WORDS
    assert len(passphrase) == AC_PASSPHRASE_LEN + AC_PASSPHRASE_NUM_WORDS - 1 \
        + AC_PASSPHRASE_NUM_BLOCKS - 1
    # exp = r'^((\d{4}-){3}\\n){2}(\d{4}-){2}\d{4}$'


def test_gen_ac_setup_payload(profile, datadir):
    ac_setup_ct = datadir.read('example-setup-message-cleartext-pyac.key')
    ac_setup_payload = gen_ac_setup_payload(ac_setup_ct, PASSPHRASE,
                                            profile)
    assert ac_setup_payload.split('\n')[:9] == \
        AC_SETUP_PAYLOAD.split('\n')[:9]


def test_gen_ac_setup_email(profile, datadir):
    ac_setup_email = gen_ac_setup_email(
        ALICE, MUTUAL, profile,
        date="Sun, 05 Nov 2017 08:44:38 GMT",
        keyhandle='71DBC5657FDE65A7',
        boundary='Y6fyGi9SoGeH8WwRaEdC6bbBcYOedDzrQ',
        passphrase=PASSPHRASE)
    assert ac_setup_email.as_string().split('\n')[:33] == \
        datadir.read('example-setup-message-pyac.eml').split('\n')[:33]


def test_parse_ac_setup_payload(profile):
    ct = parse_ac_setup_payload(AC_SETUP_PAYLOAD)
    assert AC_SETUP_ENC == ct + '\n'


def test_parse_ac_setup_ct(profile, datadir):
    pmsg = parse_ac_setup_ct(AC_SETUP_ENC, PASSPHRASE, profile)
    # NOTE: this is needed because the blob was not originally encrypted
    # with PGPy. It'll fail with other PGPy versions
    pt = pmsg.message
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    assert pt == \
        datadir.read('example-setup-message-cleartext-pyac.key').rstrip('\n')


def test_parse_ac_setup_email(profile, datadir):
    ct = datadir.read('example-setup-message-pyac.eml')
    pt = parse_ac_setup_email(ct, profile, PASSPHRASE)
    # NOTE: this is needed because the blob was not originally encrypted
    # with PGPy. It'll fail with other PGPy versions
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    assert pt == \
        datadir.read('example-setup-message-cleartext-pyac.key').rstrip('\n')


def test_parse_email(profile, datadir):
    ct = datadir.read('example-setup-message-pyac.eml')
    pt = parse_email(ct, profile, PASSPHRASE)
    pt = pt.replace('\r\n', '\n').rstrip('\n')
    assert pt == \
        datadir.read('example-setup-message-cleartext-pyac.key').rstrip('\n')

    text = datadir.read('example-gossip_pyac2.eml')
    pt = parse_email(text, profile)
    logger.debug('pt %s', pt)
    assert pt.rstrip() == \
        datadir.read('example-gossip-cleartext_pyac.eml').rstrip()
    text = datadir.read('example-simple-autocrypt-pyac.eml')
    pt = parse_ac_email(text, profile)
    assert parser.parsestr(pt).get_payload() == BODY_AC
