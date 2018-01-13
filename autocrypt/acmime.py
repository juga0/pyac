# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
# Copyright 2016, 2017 juga (juga at riseup dot net), MIT license.
from email import encoders  # ,policy
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart

from .constants import AC_SETUP_TEXT, AC_CT_SETUP, AC_CT_SETUP_FN


class MIMEMultipartACSetup(MIMEMultipart):
    """
    Base class for MIME multipart/mixed including application/autocrypt-setup.
    """
    # NOTE: policy is only introduced in Python3.6 (policy=policy.default)
    def __init__(self, _data=None, _subtype='mixed', boundary=None,
                 **_params):
        """Creates a multipart/mixed type message containing
        application/autocrypt-setup.

        By default, creates a multipart/mixed message, with proper
        Content-Type and MIME-Version headers.

        _subtype is the subtype of the multipart content type, defaulting to
        `mixed'.

        boundary is the multipart boundary string.  By default it is
        calculated as needed.

        _data is a string containing the raw payload data (encrypted).

        Additional parameters for the Content-Type header are taken from the
        keyword arguments (or passed into the _params argument).

        It will create the Email structure:
        └┬╴multipart/mixed
         ├─╴text/plain
         └─╴application/autocrypt-setup attachment
            [autocrypt-setup-message.html]

         """
        # _params['protocol'] = "?"
        description = MIMETextACSetupDescription()
        payload = MIMEApplicationACSetupPayload(_data)
        payload.add_header("Content-Disposition", 'attachment',
                           filename=AC_CT_SETUP_FN)
        _subparts = [description, payload]
        # policy is only introduced in Python3.6 (policy=policy)
        MIMEMultipart.__init__(self, _subtype, boundary, _subparts,
                               **_params)


class MIMEApplicationACSetupPayload(MIMEApplication):
    """Class for generating application/autocrypt-setup MIME documents."""

    def __init__(self, _data,
                 _subtype=AC_CT_SETUP,
                 _encoder=encoders.encode_noop, **_params):
        # policy=None,
        """Create an application/autocrypt-setup type MIME document.

        _data is a string containing the raw application data.

        _subtype is the MIME content type subtype, defaulting to
        'autocrypt-setup; name="autocrypt-setup-message.txt"'.

        _encoder is a function which will perform the actual encoding for
        transport of the application data, defaulting to noop encoding.

        Any additional keyword arguments are passed to the base class
        constructor, which turns them into parameters on the Content-Type
        header.
        """
        # NOTE: this is not needed but might be useful to add it.
        # _params["Content-Description"] = "Autocrypt Setup Message key"
        # NOTE: adding Content-Disposition as header to be able to pass
        # filename param without quoting.
        # _params["Content-Disposition"] = \
        #     'attachment; filename="autocrypt-setup-message.html"''
        # policy=policy,
        MIMEApplication.__init__(self, _data, _subtype, _encoder,
                                 **_params)


class MIMETextACSetupDescription(MIMEText):
    """Class for generating text/plain MIME documents."""

    def __init__(self, _data=AC_SETUP_TEXT, _subtype='plain'):
        """Create an text/plaind type MIME document.

        _data is a string containing by default Version: 1\n.

        _subtype is the MIME content type subtype, defaulting to
        'pgp/encrypted'.

        _encoder is a function which will perform the actual encoding for
        transport of the application data, defaulting to noop encoding.

        Any additional keyword arguments are passed to the base class
        constructor, which turns them into parameters on the Content-Type
        header.
        """
        # NOTE: this is not needed but might be useful to add it.
        # _params["Content-Description"] = \
        #    "Autocrypt Setup Message description"
        MIMEText.__init__(self, _data, _subtype)
