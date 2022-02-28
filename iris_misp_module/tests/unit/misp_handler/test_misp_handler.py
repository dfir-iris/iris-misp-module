import json
from unittest import TestCase, mock
import logging as log
from misp_handler.mispclient import MISPClient


class TestMispHandler(TestCase):
    def setUp(self) -> None:

        # Store original __import__
        orig_import = __import__
        # This will be the app module
        app_mock = mock.Mock()

        def import_mock(name, *args):
            if "app.iris_engine" in name:
                return app_mock
            if "app.datamgmt" in name:
                return app_mock
            return orig_import(name, *args)

        with mock.patch('builtins.__import__', side_effect=import_mock):
            from misp_handler import misp_handler

        self.module_conf = {
            "misp_config": '{"name": "public", "type":"public", "url":["https://testmisp"],'
                           '"key":["apikey"], "ssl":[false]}'
            ,
            "misp_http_proxy": None,
            "misp_https_proxy": None
        }

        self.misp_handler = misp_handler.MispHandler(mod_config=self.module_conf, logger=log)

    def test_load_misp_config(self):
        expected_misp_conf = {'name': 'public', 'type': 'public', 'url': ['https://testmisp'],
                              'key': ['apikey'], 'ssl': [False]}
        misp_config = self.misp_handler._load_misp_config()

        self.assertEqual(expected_misp_conf, misp_config)

    def test_load_wrong_misp_config(self):
        # Store original __import__
        orig_import = __import__
        # This will be the app module
        app_mock = mock.Mock()

        def import_mock(name, *args):
            if "app.iris_engine" in name:
                return app_mock
            if "app.datamgmt" in name:
                return app_mock
            return orig_import(name, *args)

        with mock.patch('builtins.__import__', side_effect=import_mock):
            from misp_handler import misp_handler
        wrong_module_conf = {
            "misp_config": '[{"id":0, "name": "misp0", "url":"https://someurl0", "key":"key0", "ssl":true}, {"id":1, '
                           '"name": "misp1", "url":"https://someurl1", "key":"key1", "ssl":True}]',
            "misp_http_proxy": None,
            "misp_https_proxy": None
        }

        wrong_misp_handler = misp_handler.MispHandler(mod_config=wrong_module_conf, logger=log)

        self.assertEqual(None, wrong_misp_handler._load_misp_config())

    def test_load_misp_instance(self):
        misp = self.misp_handler.load_misp_instance()

        self.assertEqual("public", misp.get("type"))
        self.assertEqual("<class 'iris_misp_module.misp_handler.mispclient.MISPClient'>", repr(type(misp.get("misp"))))
