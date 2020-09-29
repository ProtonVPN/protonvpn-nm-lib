import json
import os
import shutil

import proton
import pytest

from common import (
    CACHED_OPENVPN_CERTIFICATE, MOCK_DATA_JSON, SERVERS,
    TEST_CACHED_SERVERFILE, CertificateManager, ServerManager,
    exceptions
)

session = proton.Session.load(json.loads(MOCK_DATA_JSON))
user = os.environ["vpntest_user"]
pwd = os.environ["vpntest_pwd"]
REAL_SESSION = proton.Session("https://api.protonvpn.ch")
REAL_SESSION.authenticate(user, pwd)


class TestUnitServerManager:
    server_man = ServerManager(CertificateManager())

    @classmethod
    def setup_class(cls):
        try:
            os.mkdir(TEST_CACHED_SERVERFILE)
        except FileExistsError:
            shutil.rmtree(TEST_CACHED_SERVERFILE)
            os.mkdir(TEST_CACHED_SERVERFILE)

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(TEST_CACHED_SERVERFILE)

    def test_none_path_cache_servers(self):
        with pytest.raises(TypeError):
            self.server_man.cache_servers(
                session=REAL_SESSION, cached_serverlist=None
            )

    def test_integer_path_cache_servers(self):
        with pytest.raises(TypeError):
            self.server_man.cache_servers(
                session=REAL_SESSION, cached_serverlist=5
            )

    def test_empty_path_cache_servers(self):
        with pytest.raises(FileNotFoundError):
            self.server_man.cache_servers(
                session=REAL_SESSION, cached_serverlist=""
            )

    def test_root_path_cache_servers(self):
        with pytest.raises(IsADirectoryError):
            self.server_man.cache_servers(
                session=REAL_SESSION, cached_serverlist="/"
            )

    def test_correct_path_cache_servers(self):
        self.server_man.cache_servers(
            session=REAL_SESSION,
            cached_serverlist=os.path.join(
                TEST_CACHED_SERVERFILE, "test_cache_serverlist.json"
            )
        )

    @pytest.mark.parametrize("servername", ["#", "", 5, None, {}, []])
    def test_get_incorrect_generate_ip_list(self, servername):
        with pytest.raises(IndexError):
            self.server_man.generate_ip_list(servername, SERVERS)

    def test_get_correct_generate_ip_list(self):
        self.server_man.generate_ip_list("test#5", SERVERS)

    @pytest.fixture
    def empty_server_pool(self):
        feature = 1
        server_pool = [s for s in SERVERS if s["Features"] == feature]
        return server_pool

    @pytest.fixture
    def full_server_pool(self):
        feature = 0
        server_pool = [s for s in SERVERS if s["Features"] == feature]
        return server_pool

    def test_get_fastest_server_empty_pool(self, empty_server_pool):
        with pytest.raises(IndexError):
            self.server_man.get_fastest_server(empty_server_pool)

    def test_get_fastest_server_full_pool(self, full_server_pool):
        self.server_man.get_fastest_server(full_server_pool)

    @pytest.mark.parametrize(
        "servername",
        [
            "test#6", "test#5",
        ]
    )
    def test_correct_extract_server_value(self, servername):
        self.server_man.extract_server_value(servername, "Servers", SERVERS)

    @pytest.mark.parametrize(
        "servername",
        [
            "", "test#50",
            "#6", "test",
            123, None,
            False
        ]
    )
    def test_incorrect_extract_server_value(self, servername):
        with pytest.raises(IndexError):
            self.server_man.extract_server_value(
                servername, "Servers", SERVERS
            )

    @pytest.mark.parametrize(
        "cc,country",
        [
            ("BR", "Brazil"),
            ("BS", "Bahamas"),
            ("GR", "Greece"),
            ("GQ", "Equatorial Guinea"),
            ("GP", "Guadeloupe"),
            ("JP", "Japan"),
            ("GY", "Guyana"),
        ]
    )
    def test_correct_country_name(self, cc, country):
        assert self.server_man.extract_country_name(cc) == country

    @pytest.mark.parametrize(
        "cc,country",
        [
            ("BS", "Brazil"),
            ("BR", "Bahamas"),
            ("GQ", "Greece"),
            ("GR", "Equatorial Guinea"),
            ("JP", "Guadeloupe"),
            ("GP", "Japan"),
            ("Z", "Guyana"),
            ("", "Guyana"),
            (5, "Guyana"),
        ]
    )
    def test_incorrect_extract_country_name(self, cc, country):
        assert self.server_man.extract_country_name(cc) != country

    @pytest.mark.parametrize(
        "servername",
        [
            "PT#5",
            "SE-PT#123",
            "CH#18-TOR",
            "US-CA#999"
        ]
    )
    def test_correct_servernames(self, servername):
        resp = self.server_man.is_servername_valid(servername)
        assert resp is True

    @pytest.mark.parametrize(
        "servername",
        [
            "_#1",
            "123#412",
            "#123",
            "test2#412",
            "CH#",
            "#",
            "5",
        ]
    )
    def test_incorrect_servernames(self, servername):
        resp = self.server_man.is_servername_valid(servername)
        assert resp is False

    @pytest.mark.parametrize(
        "servername",
        [
            [], {}, 132
        ]
    )
    def test_more_incorrect_servernames(self, servername):
        with pytest.raises(TypeError):
            self.server_man.is_servername_valid(servername)


class TestIntegrationServerManager:
    server_man = ServerManager(CertificateManager())

    @classmethod
    def teardown_class(cls):
        os.remove(CACHED_OPENVPN_CERTIFICATE)

    def test_correct_generate_connect_fastest(self):
        servername, domain = self.server_man.fastest(REAL_SESSION, "tcp")
        resp = False
        if servername and domain:
            resp = True
        assert os.path.isfile(resp) is True

    @pytest.mark.parametrize(
        "session,proto",
        [
            ("", 5), (5, ""), (object, object),
            ([], []), ({}, {}), (None, None),
            (REAL_SESSION, {}), (REAL_SESSION, None)
        ]
    )
    def test_incorrect_generate_connect_fastest(
        self, session, proto
    ):
        with pytest.raises(TypeError):
            self.server_man.fastest(session, proto)

    def test_correct_generate_connect_country(self):
        args = [["cc", "ES"]]
        servername, domain = self.server_man.country_f(
            REAL_SESSION, "tcp", *args
        )
        resp = False
        if servername and domain:
            resp = True
        assert os.path.isfile(resp) is True

    @pytest.mark.parametrize(
        "session,proto,args,excp",
        [
            ("", 5, "", TypeError),
            (5, "", "", TypeError),
            (object, object, object, TypeError),
            ([], [], [], TypeError),
            (REAL_SESSION, {}, {}, TypeError),
            (REAL_SESSION, None, None, TypeError),
            (REAL_SESSION, "tcp", "test", TypeError),
            (REAL_SESSION, "tcp", "", IndexError),
            (REAL_SESSION, "tcp", None, TypeError),
            (REAL_SESSION, "tcp", [], IndexError),
            (
                REAL_SESSION, "tcp",
                [["test", "ex"]], exceptions.EmptyServerListError
            )
        ]
    )
    def test_incorrect_generate_connect_country(
        self, session, proto, args, excp
    ):
        with pytest.raises(excp):
            self.server_man.country_f(session, proto, *args)

    def test_correct_generate_connect_direct(self):
        args = [["servername", "ES#5"]]
        servername, domain = self.server_man.direct(REAL_SESSION, "tcp", *args)
        resp = False
        if servername and domain:
            resp = True
        assert os.path.isfile(resp) is True

    def test_correct_generate_connect_direct_dialog(self):
        args = ["ES#6"]
        servername, domain = self.server_man.direct(REAL_SESSION, "tcp", *args)
        resp = False
        if servername and domain:
            resp = True
        assert os.path.isfile(resp) is True

    @pytest.mark.parametrize(
        "session,proto,args,excp",
        [
            ("", 5, "", TypeError),
            (5, "", "", TypeError),
            (object, object, object, TypeError),
            ([], [], [], TypeError),
            (None, None, None, TypeError),
            (REAL_SESSION, {}, {}, TypeError),
            (REAL_SESSION, None, None, TypeError),
            (REAL_SESSION, "tcp", "test", exceptions.IllegalServername),
            (REAL_SESSION, "tcp", "", ValueError),
            (REAL_SESSION, "tcp", None, TypeError),
            (REAL_SESSION, "tcp", "test", exceptions.IllegalServername),
            (
                REAL_SESSION, "tcp",
                [["test", "ex"]], exceptions.IllegalServername
            )
        ]
    )
    def test_incorrect_generate_connect_direct(
        self, session, proto, args, excp
    ):
        with pytest.raises(excp):
            self.server_man.direct(session, proto, *args)

    def test_correct_generate_connect_feature(self):
        args = [["sc", True]]
        servername, domain = self.server_man.feature_f(
            REAL_SESSION, "tcp", *args
        )
        resp = False
        if servername and domain:
            resp = True
        assert os.path.isfile(resp) is True

    @pytest.mark.parametrize(
        "session,proto,args,excp",
        [
            ("", 5, "", TypeError),
            (5, "", "", TypeError),
            (object, object, object, TypeError),
            ([], [], [], TypeError),
            (REAL_SESSION, {}, {}, ValueError),
            (REAL_SESSION, None, None, TypeError),
            (REAL_SESSION, "tcp", "test", TypeError),
            (REAL_SESSION, "tcp", "", ValueError),
            (REAL_SESSION, "tcp", None, TypeError),
            (
                REAL_SESSION, "tcp",
                [["test", "ex"]], ValueError
            )
        ]
    )
    def test_incorrect_generate_connect_feature(
        self, session, proto, args, excp
    ):
        with pytest.raises(excp):
            self.server_man.feature_f(session, "tcp", *args)

    def test_correct_generate_connect_random(self):
        servername, domain = self.server_man.random_c(REAL_SESSION, "tcp")
        resp = False
        if servername and domain:
            resp = True
        assert os.path.isfile(resp) is True

    @pytest.mark.parametrize(
        "session,proto,excp",
        [
            ("", 5, TypeError),
            (5, "", TypeError),
            (object, object, TypeError),
            ([], [], TypeError),
            (None, None, TypeError),
            (REAL_SESSION, {}, TypeError),
            (REAL_SESSION, None, TypeError),
            (REAL_SESSION, "", ValueError)
        ]
    )
    def test_incorrect_generate_connect_random(
        self, session, proto, excp
    ):
        with pytest.raises(excp):
            self.server_man.random_c(session, proto)
