#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab 2
# Copyright 2017 juga (juga at riseup dot net), under MIT license.
"""Functions to generate and parse encrypted Email following
 Autcrypt technical specifications.
"""

import logging
import logging.config
import random
import re
import sys

from base64 import b64decode
from email import policy
from email.mime.text import MIMEText
from email.message import Message
# from email.header import Header
from email.parser import Parser

from emailpgp.mime.multipartpgp import MIMEMultipartPGP

from .acmime import MIMEMultipartACSetup
from .constants import (ADDR, KEYDATA, AC_HEADER, AC_GOSSIP,
                        AC_GOSSIP_HEADER, PE_HEADER_TYPES, NOPREFERENCE,
                        AC_HEADER_PE, PE, AC, AC_PREFER_ENCRYPT_HEADER,
                        AC_PASSPHRASE_LEN, AC_PASSPHRASE_WORD_LEN,
                        AC_PASSPHRASE_NUM_WORDS, AC_PASSPHRASE_FORMAT,
                        AC_PASSPHRASE_BEGIN_LEN, AC_PASSPHRASE_NUM_BLOCKS,
                        AC_PASSPHRASE_BEGIN, AC_SETUP_INTRO, AC_SETUP_SUBJECT,
                        AC_SETUP_MSG, LEVEL_NUMBER)

logger = logging.getLogger(__name__)
parser = Parser(policy=policy.default)


__all__ = ['wrap', 'unwrap', 'gen_headervaluestr_from_headervaluedict',
           'header_unwrap', 'header_wrap', 'gen_ac_headerdict',
           'gen_ac_headervaluestr', 'parse_header_value', 'parse_ac_headers',
           'gen_encrypted_email', 'add_headers', 'add_ac_headers',
           'gen_ac_email', 'decrypt_email', 'parse_ac_email',
           'header_unwrap_keydata', 'gen_ac_gossip_headervalue',
           'gen_ac_gossip_headervalues', 'parse_ac_gossip_headers',
           'store_gossip_keys', 'get_skey_from_msg', 'parse_ac_gossip_email',
           'gen_ac_gossip_cleartext_email', 'gen_ac_gossip_email',
           'gen_ac_setup_seckey', 'gen_ac_setup_passphrase',
           'gen_ac_setup_enc_seckey', 'gen_ac_setup_email', 'parse_email']


def wrap(text, maxlen=76, wrapstr=" "):
    """Wrap string to maxlen using wrapstr as separator.

    :param text: text to wrap
    :type text: string
    :param maxlen: maximum length
    :type maxlen: integer
    :param wrapstr: character(s) to wrap the text with
    :type pe: string
    :return: wrappedstr text
    :rtype: string
    """

    assert "\n" not in text
    return wrapstr + wrapstr.join([text[0 + i:maxlen + i]
                                 for i in range(0, len(text), maxlen)])


def unwrap(text, wrapstr='\n '):
    """Unwrap text wrapped with wrapstr."""
    return text.replace(wrapstr, '').strip()


def gen_headervaluestr_from_headervaluedict(headervaluedict):
    """Generate Email header value from a dict.

    :return: Email header value in the form: "k=v; k=v;..."
    :rtype: str
    """
    return "; ".join(["=".join([k, v]) for k, v in headervaluedict.items()])


def parse_header_value(headervaluestr):
    """Parse an Email header value.

    :param headervaluestr: an Email header value in the form:
        "addr=...; <prefer-encrypt:; >keydata=..."
    :type text: string
    :return: an Email header value dict
    :rtype: dict
    """
    # NOTE: can not just do the following, as keydata may contain "="
    # headervaluedict = dict([(k.strip(),v.strip()) for k,v in
    #                     [i.split('=') for i in header.split(';')]])
    # NOTE: email.mime splits keywords with '\n '
    header_kv_list = re.split('; |;\n ', headervaluestr)
    headervaluedict = dict()
    for kv in header_kv_list:
        if kv.startswith('addr='):
            headervaluedict[ADDR] = kv.split('addr=')[1].strip()
        elif kv.startswith('prefer-encrypt='):
            headervaluedict[PE] = kv.split('prefer-encrypt=')[1].strip()
        elif kv.startswith('keydata='):
            headervaluedict[KEYDATA] = kv.split('keydata=')[1].strip()
    return headervaluedict


def header_unwrap(headervaluestr, wrapstr="\n "):
    headervaluedict = parse_header_value(headervaluestr)
    headervaluedict['keydata'] = unwrap(headervaluedict['keydata'], wrapstr)
    return gen_headervaluestr_from_headervaluedict(headervaluedict)


def header_wrap(headervaluestr, maxlen=76, wrapstr=" "):
    headervaluedict = parse_header_value(headervaluestr)
    headervaluedict['keydata'] = wrap(headervaluedict['keydata'], maxlen, wrapstr)
    return gen_headervaluestr_from_headervaluedict(headervaluedict)


def gen_ac_headervaluestr(addr, keydata, pe=None, unwrap=False, wrapstr='\n '):
    """Generate Autocrypt Email header string.

    :param key: keydata (base 64 encoded public key)
    :type key: string or bytes
    :param addr: e-mail address
    :type addr: string
    :param pe: prefer-encrypt
    :type pe: string
    :return: Autocrypt Email header string in the form:
        {'Autocrypt': 'addr=...; <prefer-encrypt:...>; keydata=...'}
    :rtype: string

    """
    assert keydata
    assert pe in PE_HEADER_TYPES
    if isinstance(keydata, bytes):
        keydata = keydata.decode()
    if unwrap:
        keydata = unwrap(keydata, wrapstr)
    if pe is None or pe == NOPREFERENCE:
        ac_header = AC_HEADER % {ADDR: addr, KEYDATA: keydata}
    else:
        ac_header = AC_HEADER_PE % {ADDR: addr, "pe": pe,
                                    KEYDATA: keydata}
    return ac_header


def gen_ac_headerdict(addr, keydata, pe=None, unwrap=False, wrapstr='\n '):
    """Generate Autocrypt header dict.

    :return: AC header in the form:
        {'Autocrypt': 'addr=...; <prefer-encrypt:...>; keydata=...'}
    :rtype: dict
    """
    ac_header = gen_ac_headervaluestr(addr, keydata, pe, True, '\n')
    return {AC: ac_header}


def parse_ac_headers(msg):
    """Parse an Email and return a list of Autcrypt header values as dict.

    :param msg: an Email
    :type msg: string or Message
    :return: list of Autcrypt header values as dict in the form:
        [{'addr': ..., 'keydata':...}, {'addr': ..., 'keydata':...},]
    :rtype: list
    """
    if not isinstance(msg, Message):
        msg = parser.parsestr(msg)
    ac_header_list = [v.strip() for k, v in msg.items() if k == AC]
    return [parse_header_value(i) for i in ac_header_list]


def add_headers(msg, sender, recipients, subject, date=None, _dto=False,
                message_id=None, _extra=None):
    """Add headers to Email.

    :param msg: an Email Message
    :type msg: Message
    :return: an Email with headers
    :rtype: Message
    """
    logger.debug("Generating headers.")
    if _dto:
        msg["Delivered-To"] = recipients[0]
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ", ".join(recipients)
    if date:
        msg["Date"] = date
    if message_id:
        msg["Message-ID"] = message_id
    if _extra is not None:
        for name, value in _extra.items():
            msg.add_header(name, value)
    logger.debug('Generated headers.')
    return msg


def add_ac_headers(msg, sender, keydata, pe):
    """Add Autocrypt headers to Email.

    :param msg: an Email Message
    :type msg: Message
    :return: an Email with Autocrypt headers
    :rtype: Message
    """
    ac_header = gen_ac_headervaluestr(sender, keydata, pe)
    ac_header_wrappedstr = header_wrap(ac_header)
    # NOTE: maxlinelen and continuation_ws are set to defaults.
    # They should wrap long lines, but the following code wrap only text
    # from "; "
    # h = Header(ac_header_wrappedstr, maxlinelen=76, header_name="Autocrypt",
    #            continuation_ws=' ')
    # encode works as expected, but then can not add header with linefeed nor
    # carriage return
    # h_encoded = h.encode(splitchars=' ', maxlinelen=76, linesep='\n ')
    # msg['Autocrypt'] = h_encoded
    msg.add_header(AC, ac_header_wrappedstr)
    logger.debug('Generated AC headers.')
    return msg


def gen_encrypted_email(encryptedstr, boundary=None):
    """Generate encrypted/multipart Email from encrypted body.

    :param encryptedstr: an encrypted Email body
    :type encryptedstr: str
    :return: an Email Message with the encrypted str as body
    :rtype: Message
    """
    msg = MIMEMultipartPGP(encryptedstr, boundary=boundary)
    logger.debug('Generated encrypted MIME Multipart.')
    return msg


def header_unwrap_keydata(text):
    # NOTE: this would only replace the first instance found
    msg = text if isinstance(text, Message) else parser.parsestr(text)
    msg.replace_header(AC, header_unwrap(msg.get(AC)))
    ac_gossip_headers = msg.get_all(AC_GOSSIP)
    if ac_gossip_headers is not None:
        for g in ac_gossip_headers:
            msg[AC_GOSSIP] = header_unwrap(g)
    return msg.as_string()


def gen_ac_gossip_headervalue(addr, keydata):
    """Generate Autocrypt Gossip header string."""
    return AC_GOSSIP_HEADER % {ADDR: addr, KEYDATA: keydata}


# NOTE: from here functions that needs crypo
##############################################
def gen_ac_email(sender, recipients, p, subject, body, pe=None,
                 keyhandle=None, date=None, _dto=False, message_id=None,
                 boundary=None, _extra=None):
    """Generate an Autocrypt Email.

    :return: an Autocrypt encrypted Email
    :rtype: Message
    """
    if keyhandle is None:
        keyhandle = p._get_keyhandle_from_addr(sender)
    keydata = p.get_public_keydata(keyhandle, b64=True)

    data = MIMEText(body)
    enc = p.sign_encrypt(data.as_bytes(), keyhandle, recipients)
    msg = gen_encrypted_email(str(enc), boundary)
    add_headers(msg, sender, recipients, subject, date, _dto,
                message_id, _extra)
    add_ac_headers(msg, sender, keydata, pe)
    logger.info('Generated Autcrypt Email: \n%s', msg)
    return msg


def decrypt_email(msg, p, key=None):
    """Decrypt Email.

    :return: decrypted Email text
    :rtype: str
    """
    if not isinstance(msg, Message):
        msg = parser.parsestr(msg)
    assert msg.is_multipart()
    assert msg.get_content_subtype() == "encrypted"
    for payload in msg.get_payload():
        if payload.get_content_type() == 'application/octet-stream':
            enc_text = payload.get_payload()
    pt, _ = p.decrypt(enc_text, key)
    logger.info('Decrypted Email.')
    return pt.decode()


def parse_ac_email(msg, p):
    """Parse an Autocrypt Email.

    :return: an Autocrypt Email Message and decrypted body
    :rtype: Message, str
    """
    if not isinstance(msg, Message):
        msg = parser.parsestr(msg)
    ac_headers = parse_ac_headers(msg)
    if len(ac_headers) == 1:
        ac_headervaluedict = ac_headers[0]
    else:
        # TODO: error
        logger.error('There is more than one Autocrypt header.')
    p.import_keydata(b64decode(ac_headervaluedict['keydata']))
    logger.debug('Imported keydata from Autcrypt header.')
    key = get_skey_from_msg(msg, p)

    pt = decrypt_email(msg, p, key)
    logger.info('Parsed Autocrypt Email.')
    return msg, pt


def gen_ac_gossip_headervalues(recipients, p):
    """Generate Autcrypt Gossip header values.

    :return: Autcrypt Gossip header values in the form:
        ['addr=...; keydata=...', 'addr=...; keydata=...']
    :rtype: list
    """
    gossip_list = []
    for r in recipients:
        logger.debug('Generating Gossip header for recipient:\n%s', r)
        keyhandle = p._get_keyhandle_from_addr(r)
        keydata = p.get_public_keydata(keyhandle, b64=True)
        g = gen_ac_gossip_headervalue(r, keydata)
        gossip_list.append(g)
    return gossip_list


def parse_ac_gossip_headers(text):
    if not isinstance(text, Message):
        msg = parser.parsestr(text)
    else:
        msg = text
    # when
    gossip_list = [v.strip() for k, v in msg.items() if k == AC_GOSSIP]
    return gossip_list


def store_gossip_keys(gossip_list, p):
    for g in gossip_list:
        g_dict = parse_header_value(g)
        k = g_dict['keydata']
        logger.debug('Import keydata from Gossip header.')
        p.import_keydata(b64decode(k))


def get_skey_from_msg(text, p):
    if isinstance(text, str):
        msg = parser.parsestr(text)
    else:
        msg = text

    for recipient in msg['To'].split(', '):
        key = p._get_key_from_addr(recipient)
        if key is not None:
            if key.is_public:
                key = p._get_key_from_keyhandle(key.fingerprint.keyid)
                if key is not None:
                    logger.debug('Found private key for recipient %s',
                                 recipient)
                    return key
            else:
                return key
    return None


def parse_ac_gossip_email(msg, p):
    if isinstance(msg, str):
        msg = parser.parsestr(msg)
    ac_headers = parse_ac_headers(msg)
    if len(ac_headers) == 1:
        ac_headervaluedict = ac_headers[0]
    else:
        # TODO: error
        ac_headervaluedict = ac_headers[0]
    p.import_keydata(b64decode(ac_headervaluedict['keydata']))
    logger.debug('Imported keydata from Autocrypt header.')

    key = get_skey_from_msg(msg, p)
    dec_text = decrypt_email(msg, p, key)
    # NOTE: hacky workaround, because "\n" is added after "; ""
    dec_text = dec_text.replace(";\n keydata|;\r keydata|;\r\n keydata|;\n\r keydata", "; keydata")
    open('foo', 'w').write(dec_text)
    dec_msg = parser.parsestr(dec_text)
    logger.debug('dec_msg %s', dec_msg)
    gossip_list = parse_ac_gossip_headers(dec_msg)
    logger.debug('gossip_list %s', gossip_list)
    store_gossip_keys(gossip_list, p)

    return msg, dec_msg, gossip_list


def gen_ac_gossip_cleartext_email(recipients, body, p):
    gossip_headers = gen_ac_gossip_headervalues(recipients, p)
    logger.debug('gossip headers %s', gossip_headers)
    msg = MIMEText(body)
    for g in gossip_headers:
        msg[AC_GOSSIP] = g
    return msg


def gen_ac_gossip_email(sender, recipients, p, subject, body, pe=None,
                        keyhandle=None, date=None, _dto=False, message_id=None,
                        boundary=None, _extra=None):
    """."""
    if keyhandle is None:
        keyhandle = p._get_keyhandle_from_addr(sender)
    keydata = p.get_public_keydata(keyhandle, b64=True)

    msg_clear = gen_ac_gossip_cleartext_email(recipients, body, p)

    enc = p.sign_encrypt(msg_clear.as_bytes(), keyhandle, recipients)
    msg = gen_encrypted_email(str(enc), boundary=boundary)
    logger.debug(msg)
    add_headers(msg, sender, recipients, subject,
                      date, _dto, message_id, _extra)
    add_ac_headers(msg, sender, keydata, pe)
    return msg


def gen_ac_setup_seckey(sender, pe, p, keyhandle=None):
    if keyhandle is None:
        keyhandle = p._get_keyhandle_from_addr(sender)
    seckey = p.get_secret_keydata(keyhandle, armor=True)
    seckey_list = seckey.split('\n')
    seckey_list.insert(2, AC_PREFER_ENCRYPT_HEADER + pe)
    ac_setup_seckey = "\n".join(seckey_list)
    return ac_setup_seckey


def gen_ac_setup_passphrase():
    numbers = [str(random.randrange(0, 9))
               for i in range(0, AC_PASSPHRASE_LEN)]
    passphrase = "-".join(["".join(numbers[0+i:AC_PASSPHRASE_WORD_LEN+i])
                           for i in range(0, AC_PASSPHRASE_NUM_WORDS)])
    len_block = (len(passphrase) + 1) // AC_PASSPHRASE_NUM_BLOCKS
    passphrase_blocks_list = [passphrase[0+i:len_block+i]
                              for i in range(0, len(passphrase), len_block)]
    passphrase_blocks = "\n".join(passphrase_blocks_list)
    logger.info(passphrase_blocks)
    return passphrase_blocks


def gen_ac_setup_enc_seckey(ac_setup_seckey, passphrase, p):
    encmsg = p.sym_encrypt(ac_setup_seckey, passphrase)
    encmsg_list = str(encmsg).split('\n')
    encmsg_list.insert(2, AC_PASSPHRASE_FORMAT + "\n" +
                       AC_PASSPHRASE_BEGIN +
                       passphrase[:AC_PASSPHRASE_BEGIN_LEN])
    ac_setup_enctext = "\n".join(encmsg_list)
    return AC_SETUP_INTRO + "\n" + ac_setup_enctext


def gen_ac_setup_email(sender, pe, p, subject=AC_SETUP_SUBJECT, body=None,
                       keyhandle=None, date=None, _dto=False, message_id=None,
                       boundary=None, _extra=None, passphrase=None):
    passphrase = passphrase or gen_ac_setup_passphrase()
    ac_setup_seckey = gen_ac_setup_seckey(sender, pe, p, keyhandle)
    ac_setup_enc_seckey = gen_ac_setup_enc_seckey(ac_setup_seckey,
                                                  passphrase, p)
    msg = MIMEMultipartACSetup(ac_setup_enc_seckey, boundary=boundary)
    if _extra is None:
        _extra = {}
    _extra.update({AC_SETUP_MSG: LEVEL_NUMBER})
    add_headers(msg, sender, [sender], subject,
                date, _dto, message_id, _extra)
    logger.debug('Generated multipart AC Setup body.')
    return msg


def parse_ac_setup_header(msg):
    if isinstance(msg, str):
        msg = parser.parsestr(msg)
    return msg.get(AC_SETUP_MSG)


def parse_ac_setup_enc_part(enctext, passphrase, p):
    enctext_list = enctext.split('\n')
    pass_format = enctext_list.pop(2)
    if pass_format != AC_PASSPHRASE_FORMAT:
        logger.error('Passphrase format not found.')
    pass_begins = enctext_list.pop(2)
    if pass_begins[:len(AC_PASSPHRASE_BEGIN)] != AC_PASSPHRASE_BEGIN:
        logger.error('{} not found.'.format(AC_PASSPHRASE_BEGIN))
    if pass_begins[AC_PASSPHRASE_BEGIN_LEN:] != \
            passphrase[:AC_PASSPHRASE_BEGIN_LEN]:
        logger.error('The passphrase is invalid.')
    logger.debug('Encrypted part without headers %s', "\n".join(enctext_list))
    plainmsg = p.sym_decrypt("\n".join(enctext_list), passphrase)
    return plainmsg


def parse_ac_setup_payload(payload):
    if isinstance(payload, str):
        payload = parser.parsestr(payload)
    filename = payload.get_filename()
    attachment_text = payload.get_payload()
    if filename:
        with open(filename, 'w') as fp:
            fp.write(attachment_text)
    enc_starts = attachment_text.find('-----BEGIN PGP MESSAGE-----')
    bodytext = attachment_text[:enc_starts]
    logger.info(bodytext)
    enc_ends = attachment_text.find('-----END PGP MESSAGE-----')
    enctext = attachment_text[enc_starts:enc_ends] + '-----END PGP MESSAGE-----'
    logger.debug('enctext %s', enctext)
    return enctext


def parse_ac_setup_email(msg, p, passphrase):
    if isinstance(msg, str):
        msg = parser.parsestr(msg)
    if msg.get(AC_SETUP_MSG) != LEVEL_NUMBER:
        logger.error('This is not an Autocrypt Setup Message v1')
    description, payload = msg.get_payload()
    logger.info(description.as_string())

    enctext = parse_ac_setup_payload(payload)
    plainmsg = parse_ac_setup_enc_part(enctext, passphrase, p)
    p.import_keydata(plainmsg.message)
    logger.info('Secret key imported.')
    return plainmsg


def parse_email(msg, p, passphrase=None):
    if isinstance(msg, str):
        msg = parser.parsestr(msg)
    if msg.get(AC_SETUP_MSG) == LEVEL_NUMBER:
        logger.info('Email is an Autocrypt Setup Message.')
        if passphrase is None:
            passphrase = sys.raw_input('Introduce the passphrase:\n')
        return parse_ac_setup_email(msg, p, passphrase)
    elif msg.get(AC) is not None:
        logger.info('Email contains Autocrypt headers.')
        msg, pt = parse_ac_email(msg, p)
        if parser.parsestr(pt).get(AC_GOSSIP) is not None:
            return parse_ac_gossip_email(msg, p)
    elif msg.get(AC_GOSSIP) is not None:
        logger.info('Email contains Autocrypt Gossip headers.')
        return parse_ac_gossip_email(msg, p)
