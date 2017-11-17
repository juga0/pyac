"""For compatibility with previous py-autocrypt code."""

from base64 import b64encode


def b64encode_u(x):
    res = b64encode(x)
    if isinstance(res, bytes):
        res = res.decode("ascii")
    return res
