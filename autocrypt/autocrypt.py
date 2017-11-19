#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""Script to generate and parse encrypted Email following
 Autcrypt technical specifications.
 """

import argparse
import logging
import logging.config
import os.path

from .conflog import LOGGING
from .constants import BASE_DIR, MUTUAL
from .examples_data import PGPHOME
from .pgpycrypto import PGPyCrypto
from .pgpymessage import (gen_ac_email, gen_gossip_email, gen_ac_setup_email,
                          parse_email, gen_ac_setup_passphrase)

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('autocrypt')
DATAPATH = os.path.join(BASE_DIR, "tests", "data")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug',
                        help='Set logging level to debug',
                        action='store_true')
    parser.add_argument('-m', '--pgphome',
                        help='Path to Autocrypt home',
                        default=PGPHOME)
    parser.add_argument('-f', '--sender',
                        help='Email sender address and OpenPGP UID',
                        default='alice@autocrypt.example')
    parser.add_argument('-t', '--recipients',
                        help='Email recipient addresses separatade by comma',
                        default='bob@autocrypt.example,'
                                'carol@autocrypt.example')
    parser.add_argument('-n', '--genkey',
                        help='Generate a OpenPGP key pair',
                        action='store_true')
    parser.add_argument('-p', '--parse',
                        help='Parse Email',
                        action='store_true')
    parser.add_argument('-i', '--input',
                        help='Path to input Email to parse',
                        default=os.path.join(
                            DATAPATH,
                            'example-simple-autocrypt-pyac.eml'))
    parser.add_argument('-a', '--genac',
                        help='Generate Autocrypt Email',
                        action='store_true')
    parser.add_argument('-u', '--subject',
                        help='Subject for the Autocrypt Email',
                        default='Subject')
    parser.add_argument('-e', '--pe',
                        help='prefer-encrypt for the Autocrypt Email',
                        default=MUTUAL)
    parser.add_argument('-b', '--body',
                        help='Body for the Autocrypt Email',
                        default='Body')
    parser.add_argument('-g', '--genag',
                        help='Generate Autocrypt Gossip Email',
                        action='store_true')
    parser.add_argument('-s', '--genas',
                        help='Generate Autocrypt Setup Email',
                        action='store_true')
    parser.add_argument('-r', '--passphrase',
                        help='Passphrase to generate an Autocrypt Setup Email',
                        default=None)
    parser.add_argument('-c', '--genasc',
                        help='Generate Autocrypt Setup Code',
                        action='store_true')
    parser.add_argument('-o', '--output',
                        help='Path to store the Autocrypt Email',
                        default='/tmp/output.eml')
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    logger.debug('args %s', args)

    p = PGPyCrypto(args.pgphome)

    if args.genkey:
        p.gen_secret_key(emailadr=args.sender)

    if args.parse:
        pt = open(args.input).read()
        msg = parse_email(pt, p)
        logger.info('Parsed Email: \n%s', msg)
    msg = None
    if args.genac:
        msg = gen_ac_email(args.sender, args.recipients.split(','), p,
                           args.subject, args.body, args.pe)
    if args.genag:
        msg = gen_gossip_email(args.sender, args.recipients.split(','), p,
                               args.subject, args.body, args.pe)
    if args.genas:
        if args.passphrase is None:
            args.passphrase = gen_ac_setup_passphrase()
        msg = gen_ac_setup_email(args.sender, args.pe, p,
                                 passphrase=args.passphrase)
    if args.genasc:
        gen_ac_setup_passphrase()
    if args.output and msg is not None:
        open(args.output, 'w').write(msg.as_string())


if __name__ == '__main__':
    main()
