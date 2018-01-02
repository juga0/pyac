# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

import pytest

from autocrypt.storage import load


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
def profile_maker(request, datadir):
    def maker():
        path = datadir.join('profile.json')
        profile = load(path)
        return profile
    return maker


@pytest.fixture
def profile(profile_maker):
    return profile_maker()
