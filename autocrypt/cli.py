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

from autocrypt import __version__
from .conflog import LOGGING
from .constants import BASE_DIR, MUTUAL
from .tests_data import PGPHOME
from .message import (gen_ac_email, gen_gossip_email, gen_ac_setup_email,
                      parse_email, gen_ac_setup_passphrase)
from .storage import load, new_account, new_peer, repr_profile

logging.config.dictConfig(LOGGING)
logger = logging.getLogger('autocrypt')
DATAPATH = os.path.join(BASE_DIR, "tests", "data")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version',
                        version='%(prog)s ' + __version__)

    parser.add_argument('-d', '--debug',
                        help='Set logging level to debug',
                        action='store_true')
    parser.add_argument('-m', '--pgphome',
                        help='Path to Autocrypt home, ~/.pyac by default',
                        default=PGPHOME)

    parser.add_argument('-l', '--list',
                        help='List account and peers',
                        action='store_true')

    parser.add_argument('-n', '--newaccount',
                        help="""Email address for the new account.
                        It will also generate new OpenPGP keys.""",
                        default='alice@autocrypt.example')
    parser.add_argument('-r', '--newpeer',
                        help="""Email address for the new peer.""",
                        default='bob@autocrypt.example,')

    parser.add_argument('-a', '--genac',
                        help="""Generate Autocrypt Email.
                        Use -f, -t, -s, -b, or the defaults will be use""",
                        action='store_true')

    parser.add_argument('-g', '--genag',
                        help='Generate Autocrypt Gossip Email',
                        action='store_true')
    parser.add_argument('-u', '--genas',
                        help='Generate Autocrypt Setup Email',
                        action='store_true')
    parser.add_argument('-p', '--passphrase',
                        help='Passphrase to generate an Autocrypt Setup Email',
                        default=None)
    parser.add_argument('-c', '--genasc',
                        help='Generate Autocrypt Setup Code',
                        action='store_true')

    parser.add_argument('-f', '--fromh',
                        help='Email sender address and OpenPGP UID',
                        default='alice@autocrypt.example')
    parser.add_argument('-t', '--to',
                        help='Email recipient addresses separatade by comma',
                        default='bob@autocrypt.example,'
                                'carol@autocrypt.example')
    parser.add_argument('-s', '--subject',
                        help='Subject for the Autocrypt Email',
                        default='Subject')
    parser.add_argument('-b', '--body',
                        help='Body for the Autocrypt Email',
                        default='Body')
    parser.add_argument('-e', '--pe',
                        help='prefer-encrypt for the Autocrypt Email',
                        default=MUTUAL)

    parser.add_argument('-i', '--input',
                        help='Path to the Email to parse, by default: %s' %
                        os.path.join(DATAPATH,
                                     'example-simple-autocrypt-pyac.eml'),
                        default=os.path.join(
                            DATAPATH,
                            'example-simple-autocrypt-pyac.eml'))

    parser.add_argument('-o', '--output',
                        help="""Path to store the Autocrypt Email, by default:
                        /tmp/output.eml""",
                        default='/tmp/output.eml')

    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    logger.debug('args %s', args)

    profile = load()
    msg = None

    if args.list:
        logger.info(repr_profile(profile))

    if args.newaccount is not None:
        new_account(profile, args.newaccount)

    if args.newpeer is not None:
        new_peer(profile, args.newpeer)

    if args.genac:
        msg = gen_ac_email(args.fromh, args.to.split(','), profile,
                           args.subject, args.body, args.pe)
    if args.genag:
        msg = gen_gossip_email(args.fromh, args.to.split(','),
                               profile, args.subject, args.body, args.pe)
    if args.genasc:
        gen_ac_setup_passphrase()

    if args.genas:
        if args.passphrase is None:
            args.passphrase = gen_ac_setup_passphrase()
        msg = gen_ac_setup_email(args.fromh, args.pe, profile,
                                 passphrase=args.passphrase)

    if args.input is not None:
        pt = open(args.input).read()
        msg = parse_email(pt, profile)
        logger.info('Parsed Email: \n%s', msg)

    if msg is not None:
        open(args.output, 'w').write(msg.as_string())


if __name__ == '__main__':
    main()
