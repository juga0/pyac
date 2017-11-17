"""For compatibility with previous py-autocrypt code."""

from __future__ import print_function, unicode_literals


class KeyInfo:
    def __init__(self, type, bits, id, uid, date_created):
        self.type = type
        self.bits = int(bits)
        self.id = id
        self.uids = [uid] if uid else []
        self.date_created = date_created

    def match(self, other_id):
        i = min(len(other_id), len(self.id))
        return self.id[-i:] == other_id[-i:]

    def __str__(self):
        return "KeyInfo(id={id!r}, uids={uids!r}, bits={bits}, type={type})".format(
            **self.__dict__)

    __repr__ = __str__
