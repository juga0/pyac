# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

import itertools
import pytest
from autocrypt.crypto import PGPyCrypto


@pytest.fixture
def tmpdir(tmpdir_factory, request):
    base = str(hash(request.node.nodeid))[:3]
    bn = tmpdir_factory.mktemp(base)
    return bn


@pytest.fixture()
def datadir(request):
    """ get, read, open test files from the "data" directory. """
    class D:
        def __init__(self, basepath):
            self.basepath = basepath

        def open(self, name, mode="r"):
            return self.basepath.join(name).open(mode)

        def join(self, name):
            return self.basepath.join(name).strpath

        def read_bytes(self, name):
            with self.open(name, "rb") as f:
                return f.read()

        def read(self, name):
            with self.open(name, "r") as f:
                return f.read()

    return D(request.fspath.dirpath("data"))


@pytest.fixture
def crypto_maker(request, tmpdir, datadir):
    """Return a function which creates initialized PGPyCrypto instances."""
    counter = itertools.count()

    def maker(native=False, pgphome=None):
        if pgphome:
            p = datadir.join('pgphome')
        else:
            p = tmpdir.join("pgpycrypto%d" % next(counter))
        pgpycrypto = PGPyCrypto(p)
        return pgpycrypto
    return maker


@pytest.fixture
def pgpycrypto(crypto_maker):
    """Return an initialized pgpycrypto instance."""
    return crypto_maker()


@pytest.fixture
def pgphome_maker(request, datadir):
    def maker():
        p = datadir.join('pgphome')
        pgpycrypto = PGPyCrypto(p)
        return pgpycrypto
    return maker


@pytest.fixture
def pcrypto(pgphome_maker):
    return pgphome_maker()
