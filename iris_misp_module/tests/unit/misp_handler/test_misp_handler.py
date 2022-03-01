from unittest import TestCase, mock
import logging as log
import iris_interface.IrisInterfaceStatus as InterfaceStatus


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
                           '"key":["<apikey>>"], "ssl":[false]}'
            ,
            "misp_http_proxy": None,
            "misp_https_proxy": None,
            "misp_report_as_attribute": True,
            "misp_domain_report_template": "<div class=\"row\">\n    <div class=\"col-12\">\n        <div "
                                           "class=\"accordion\">\n            <h3>MISP raw results</h3>\n\n           "
                                           " <div class=\"card\">\n                <div class=\"card-header "
                                           "collapsed\" id=\"drop_r\" data-toggle=\"collapse\" "
                                           "data-target=\"#drop_raw\" aria-expanded=\"false\" "
                                           "aria-controls=\"drop_raw\" role=\"button\">\n                    <div "
                                           "class=\"span-icon\">\n                        <div "
                                           "class=\"flaticon-file\"></div>\n                    </div>\n              "
                                           "      <div class=\"span-title\">\n                        MISP raw "
                                           "results\n                    </div>\n                    <div "
                                           "class=\"span-mode\"></div>\n                </div>\n                <div "
                                           "id=\"drop_raw\" class=\"collapse\" aria-labelledby=\"drop_r\" "
                                           "style=\"\">\n                    <div class=\"card-body\">\n              "
                                           "          <div id='misp_raw_ace'>{{ results| tojson(indent=4) }}</div>\n  "
                                           "                  </div>\n                </div>\n            </div>\n    "
                                           "    </div>\n    </div>\n</div> \n<script>\nvar misp_in_raw = ace.edit("
                                           "\"misp_raw_ace\",\n{\n    autoScrollEditorIntoView: true,\n    minLines: "
                                           "30,\n});\nmisp_in_raw.setReadOnly(true);\nmisp_in_raw.setTheme("
                                           "\"ace/theme/tomorrow\");\nmisp_in_raw.session.setMode("
                                           "\"ace/mode/json\");\nmisp_in_raw.renderer.setShowGutter("
                                           "true);\nmisp_in_raw.setOption(\"showLineNumbers\", "
                                           "true);\nmisp_in_raw.setOption(\"showPrintMargin\", "
                                           "false);\nmisp_in_raw.setOption(\"displayIndentGuides\", "
                                           "true);\nmisp_in_raw.setOption(\"maxLines\", "
                                           "\"Infinity\");\nmisp_in_raw.session.setUseWrapMode("
                                           "true);\nmisp_in_raw.setOption(\"indentedSoftWrap\", "
                                           "true);\nmisp_in_raw.renderer.setScrollMargin(8, 5);\n</script> "
        }

        self.misp_handler = misp_handler.MispHandler(mod_config=self.module_conf, logger=log)

    def test_load_misp_config(self):
        expected_misp_conf = {'name': 'public', 'type': 'public', 'url': ['https://testmisp'],
                              'key': ['<apikey>'], 'ssl': [False]}
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

    def test_handle_misp_domain(self):
        class Ioc:
            __tablename__ = 'ioc'

            ioc_value = str

        mock_ioc = Ioc()
        mock_ioc.ioc_value = "kavkazjlhad.com"

        self.misp_handler.load_misp_instance()

        self.assertEqual(InterfaceStatus.I2Success(), self.misp_handler.handle_misp_domain(mock_ioc))
