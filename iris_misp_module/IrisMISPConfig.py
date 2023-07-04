#!/usr/bin/env python3
#
#  IRIS MISP Module Source Code
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

module_name = "IrisMISP"
module_description = "Provides an interface between MISP and IRIS"
interface_version = "1.2.0"
module_version = "1.2.0"
pipeline_support = False
pipeline_info = {}

module_configuration = [
    {
        "param_name": "misp_config",
        "param_human_name": "MISP configuration",
        "param_description": "Configure one or several MISP instances",
        "default": "{\n"
        "   \"name\": \"Public_MISP\",\n"
        "   \"type\":\"public\",\n"
        "   \"url\":[\"https://URL\"],\n"
        "   \"key\":[\"APIKEY\"],\n"
        "   \"ssl\":[false]\n"
        "}",
        "mandatory": True,
        "type": "textfield_json"
    },
    {
        "param_name": "misp_http_proxy",
        "param_human_name": "MISP HTTP Proxy",
        "param_description": "HTTP Proxy parameter",
        "default": None,
        "mandatory": False,
        "type": "string"
    },
    {
        "param_name": "misp_https_proxy",
        "param_human_name": "MISP HTTPS Proxy",
        "param_description": "HTTPS Proxy parameter",
        "default": None,
        "mandatory": False,
        "type": "string"
    },
    {
        "param_name": "misp_report_as_attribute",
        "param_human_name": "Add MISP report as new IOC attribute",
        "param_description": "Creates a new attribute on the IOC, base on the MISP report. Attributes are based "
                             "on the templates of this configuration",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },
    {
        "param_name": "misp_domain_report_template",
        "param_human_name": "Domain report template",
        "param_description": "Domain report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <div "
                   "class=\"accordion\">\n            <h3>MISP raw results</h3>\n\n           "
                   " <div class=\"card\">\n                <div class=\"card-header "
                   "collapsed\" id=\"drop_r_misp\" data-toggle=\"collapse\" "
                   "data-target=\"#drop_raw_misp\" aria-expanded=\"false\" "
                   "aria-controls=\"drop_raw_misp\" role=\"button\">\n                    <div "
                   "class=\"span-icon\">\n                        <div "
                   "class=\"flaticon-file\"></div>\n                    </div>\n              "
                   "      <div class=\"span-title\">\n                        MISP raw "
                   "results\n                    </div>\n                    <div "
                   "class=\"span-mode\"></div>\n                </div>\n                <div "
                   "id=\"drop_raw_misp\" class=\"collapse\" aria-labelledby=\"drop_r_misp\" "
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
                   "true);\nmisp_in_raw.renderer.setScrollMargin(8, 5);\n</script> ",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "misp_ip_report_template",
        "param_human_name": "IP report template",
        "param_description": "IP report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <div "
                   "class=\"accordion\">\n            <h3>MISP raw results</h3>\n\n           "
                   " <div class=\"card\">\n                <div class=\"card-header "
                   "collapsed\" id=\"drop_r_misp\" data-toggle=\"collapse\" "
                   "data-target=\"#drop_raw_misp\" aria-expanded=\"false\" "
                   "aria-controls=\"drop_raw_misp\" role=\"button\">\n                    <div "
                   "class=\"span-icon\">\n                        <div "
                   "class=\"flaticon-file\"></div>\n                    </div>\n              "
                   "      <div class=\"span-title\">\n                        MISP raw "
                   "results\n                    </div>\n                    <div "
                   "class=\"span-mode\"></div>\n                </div>\n                <div "
                   "id=\"drop_raw_misp\" class=\"collapse\" aria-labelledby=\"drop_r_misp\" "
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
                   "true);\nmisp_in_raw.renderer.setScrollMargin(8, 5);\n</script> ",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "misp_hash_report_template",
        "param_human_name": "Hash report template",
        "param_description": "Hash report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <div "
                   "class=\"accordion\">\n            <h3>MISP raw results</h3>\n\n           "
                   " <div class=\"card\">\n                <div class=\"card-header "
                   "collapsed\" id=\"drop_r_misp\" data-toggle=\"collapse\" "
                   "data-target=\"#drop_raw_misp\" aria-expanded=\"false\" "
                   "aria-controls=\"drop_raw_misp\" role=\"button\">\n                    <div "
                   "class=\"span-icon\">\n                        <div "
                   "class=\"flaticon-file\"></div>\n                    </div>\n              "
                   "      <div class=\"span-title\">\n                        MISP raw "
                   "results\n                    </div>\n                    <div "
                   "class=\"span-mode\"></div>\n                </div>\n                <div "
                   "id=\"drop_raw_misp\" class=\"collapse\" aria-labelledby=\"drop_r_misp\" "
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
                   "true);\nmisp_in_raw.renderer.setScrollMargin(8, 5);\n</script> ",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "misp_ja3_report_template",
        "param_human_name": "JA3 report template",
        "param_description": "JA3 report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <div "
                   "class=\"accordion\">\n            <h3>MISP raw results</h3>\n\n           "
                   " <div class=\"card\">\n                <div class=\"card-header "
                   "collapsed\" id=\"drop_r_misp\" data-toggle=\"collapse\" "
                   "data-target=\"#drop_raw_misp\" aria-expanded=\"false\" "
                   "aria-controls=\"drop_raw_misp\" role=\"button\">\n                    <div "
                   "class=\"span-icon\">\n                        <div "
                   "class=\"flaticon-file\"></div>\n                    </div>\n              "
                   "      <div class=\"span-title\">\n                        MISP raw "
                   "results\n                    </div>\n                    <div "
                   "class=\"span-mode\"></div>\n                </div>\n                <div "
                   "id=\"drop_raw_misp\" class=\"collapse\" aria-labelledby=\"drop_r_misp\" "
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
                   "true);\nmisp_in_raw.renderer.setScrollMargin(8, 5);\n</script> ",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "misp_manual_hook_enabled",
        "param_human_name": "Manual triggers on IOCs",
        "param_description": "Set to True to offers possibility to manually triggers the module via the UI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "misp_on_create_hook_enabled",
        "param_human_name": "Triggers automatically on IOC create",
        "param_description": "Set to True to automatically add a MISP insight each time an IOC is created",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "misp_on_update_hook_enabled",
        "param_human_name": "Triggers automatically on IOC update",
        "param_description": "Set to True to automatically add a MISP insight each time an IOC is updated",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    }
]
