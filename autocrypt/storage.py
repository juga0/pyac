#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
""".
"""
import logging
import json
import os
import os.path
from shutil import copyfile

from .conflog import LOGGING
from .constants import (ACCOUNTS, ACTIMESTAMP, GOSSIPKEY, GOSSIPTS,
                        INITIALDATA, LASTSEEN, NOPREFERENCE, PEERS,
                        PREFERENCRYPT, PROFILE_PATH, PUBKEY, SECKEY)
from .crypto_func import gen_key, _key2keydatas

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('autocrypt')


def save(datadict, jpath=PROFILE_PATH):
    if not os.path.exists(os.path.dirname(jpath)):
        os.makedirs(jpath)
        copyfile(INITIALDATA, jpath)
    with open(jpath, 'w') as fp:
        json.dump(datadict, fp, indent=2)
    logger.debug('Wrote profile in %s', jpath)


def load(jpath=PROFILE_PATH):
    if not os.path.isfile(jpath):
        return {ACCOUNTS: {}, PEERS: {}}
    with open(jpath) as fp:
        return json.load(fp)


def new_account(profile, addr, sk=None, pk=None, pe=None):
    if sk is None:
        key = gen_key(addr)
        sk, pk = _key2keydatas(key)
    else:
        assert pk is not None
    profile[ACCOUNTS][addr] = {
        SECKEY: sk,
        PUBKEY: pk,
        PREFERENCRYPT: pe
    }
    save(profile)


def del_account(profile, addr):
    del(profile[ACCOUNTS][addr])


def new_peer(profile, addr, pk=None, pe=NOPREFERENCE, ls=None, ats=None,
             gpk=None, gts=None):
    profile[PEERS][addr] = {
        PUBKEY: pk,
        PREFERENCRYPT: pe,
        LASTSEEN: ls,
        ACTIMESTAMP: ats,
        GOSSIPKEY: gpk,
        GOSSIPTS: gts
    }
    save(profile)


def del_peer(profile, addr):
    del(profile[PEERS][addr])


def repr_account(profile, addr):
    s = "\n{}\n--------------------\n".format(addr)
    s += "\n".join([": ".join([k, str(v)])
                    for k, v in profile[ACCOUNTS][addr].items()
                    if k not in [PUBKEY, SECKEY]])
    return s


def repr_peer(profile, addr):
    s = "\n{}\n--------------------\n".format(addr)
    s += "\n".join([": ".join([k, str(v)])
                    for k, v in profile[PEERS][addr].items()
                    if k not in [PUBKEY, GOSSIPKEY]])
    return s


def repr_accounts(profile):
    s = "\nAccounts\n==========\n"
    s += "\n".join([repr_account(profile, addr)
                    for addr in profile[ACCOUNTS].keys()])
    return s


def repr_peers(profile):
    s = "\nPeers\n==========\n"
    s += "\n".join([repr_peer(profile, addr)
                    for addr in profile[PEERS].keys()])
    return s


def repr_profile(profile):
    s = "\n".join([repr_accounts(profile), repr_peers(profile)])
    return s
