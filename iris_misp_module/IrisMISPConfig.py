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
interface_version = 1.1
module_version = 1.0
pipeline_support = False
pipeline_info = {}

module_configuration = [
    {
        "param_name": "misp_config",
        "param_human_name": "MISP configuration",
        "param_description": "Configure one or several MISP instances",
        "default": "{}",
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
        "param_description": "Domain reports template used to add a new custom attribute to the target IOC",
        "default": "{% if nb_detected_urls %}\n<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>Detected "
                   "URLS</h3>\n        <dl class=\"row\">\n            <dt class=\"col-sm-3\">Total detected "
                   "URLs</dt>\n            <dd class=\"col-sm-9\">{{ nb_detected_urls }}</dd>\n            \n         "
                   "   <dt class=\"col-sm-3\">Average detection ratio</dt>\n            <dd class=\"col-sm-9\">{{ "
                   "avg_urls_detect_ratio }}</dd>\n        </dl>\n    </div>\n</div>    \n{% endif %}\n\n{% if "
                   "nb_detected_samples %}\n<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>Detected "
                   "samples</h3>\n        <dl class=\"row\">\n            <dt class=\"col-sm-3\">Total detected "
                   "samples</dt>\n            <dd class=\"col-sm-9\">{{ nb_detected_samples }}</dd>\n            \n   "
                   "         <dt class=\"col-sm-3\">Average detection ratio</dt>\n            <dd "
                   "class=\"col-sm-9\">{{ avg_samples_detect_ratio }}</dd>\n        </dl>\n    </div>\n</div>    \n{% "
                   "endif %}\n\n<div class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n  "
                   "          <h3>Additional information</h3>\n            {% if whois %}\n            <div "
                   "class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_wh\" "
                   "data-toggle=\"collapse\" data-target=\"#drop_whois\" aria-expanded=\"false\" "
                   "aria-controls=\"drop_resolutions\" role=\"button\">\n                    <div "
                   "class=\"span-icon\">\n                        <div class=\"flaticon-user-6\"></div>\n             "
                   "       </div>\n                    <div class=\"span-title\">\n                        WHOIS\n    "
                   "                </div>\n                    <div class=\"span-mode\"></div>\n                "
                   "</div>\n                <div id=\"drop_whois\" class=\"collapse\" aria-labelledby=\"drop_wh\" "
                   "style=\"\">\n                    <div class=\"card-body\">\n                        <blockquote "
                   "class=\"blockquote\">\n                            {% autoescape false %}\n                       "
                   "     <p>{{ whois| replace(\"\\n\", \"<br/>\") }}</p>\n                            {% "
                   "endautoescape %}\n                        </blockquote>\n                    </div>\n             "
                   "   </div>\n            </div>\n            {% endif %}\n    \n            {% if resolutions %}\n  "
                   "          <div class=\"card\">\n                <div class=\"card-header collapsed\" "
                   "id=\"drop_res\" data-toggle=\"collapse\" data-target=\"#drop_resolutions\" "
                   "aria-expanded=\"false\" aria-controls=\"drop_resolutions\" role=\"button\">\n                    "
                   "<div class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n          "
                   "          </div>\n                    <div class=\"span-title\">\n                        "
                   "Resolutions history\n                    </div>\n                    <div "
                   "class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_resolutions\" "
                   "class=\"collapse\" aria-labelledby=\"drop_res\" style=\"\">\n                    <div "
                   "class=\"card-body\">\n                        <ul>\n                            {% for resolution "
                   "in resolutions %} \n                            <li>{{resolution.ip_address}} ( Last resolved on "
                   "{{resolution.last_resolved}} )</li>\n                            {% endfor %}\n                   "
                   "     </ul>\n                    </div>\n                </div>\n            </div>\n            {"
                   "% endif %}\n            \n            {% if subdomains %}\n            <div class=\"card\">\n     "
                   "           <div class=\"card-header collapsed\" id=\"drop_sub\" data-toggle=\"collapse\" "
                   "data-target=\"#drop_subdomains\" aria-expanded=\"false\" aria-controls=\"drop_subdomains\" "
                   "role=\"button\">\n                    <div class=\"span-icon\">\n                        <div "
                   "class=\"flaticon-diagram\"></div>\n                    </div>\n                    <div "
                   "class=\"span-title\">\n                        Subdomains\n                    </div>\n           "
                   "         <div class=\"span-mode\"></div>\n                </div>\n                <div "
                   "id=\"drop_subdomains\" class=\"collapse\" aria-labelledby=\"drop_sub\" style=\"\">\n              "
                   "      <div class=\"card-body\">\n                        <ul>\n                            {% for "
                   "subdomain in subdomains %} \n                            <li>{{subdomain}}</li>\n                 "
                   "           {% endfor %}\n                        </ul>\n                    </div>\n              "
                   "  </div>\n            </div>\n            {% endif %}\n        </div>\n    </div>\n</div>\n\n<div "
                   "class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n            "
                   "<h3>Raw report</h3>\n\n            <div class=\"card\">\n                <div class=\"card-header "
                   "collapsed\" id=\"drop_r\" data-toggle=\"collapse\" data-target=\"#drop_raw\" "
                   "aria-expanded=\"false\" aria-controls=\"drop_raw\" role=\"button\">\n                    <div "
                   "class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n               "
                   "     </div>\n                    <div class=\"span-title\">\n                        Raw report\n "
                   "                   </div>\n                    <div class=\"span-mode\"></div>\n                "
                   "</div>\n                <div id=\"drop_raw\" class=\"collapse\" aria-labelledby=\"drop_r\" "
                   "style=\"\">\n                    <div class=\"card-body\">\n                        <div "
                   "id='vt_raw_ace'>{{ results| tojson(indent=4) }}</div>\n                    </div>\n               "
                   " </div>\n            </div>\n        </div>\n    </div>\n</div> \n<script>\nvar vt_in_raw = "
                   "ace.edit(\"vt_raw_ace\",\n{\n    autoScrollEditorIntoView: true,\n    minLines: 30,"
                   "\n});\nvt_in_raw.setReadOnly(true);\nvt_in_raw.setTheme("
                   "\"ace/theme/tomorrow\");\nvt_in_raw.session.setMode("
                   "\"ace/mode/json\");\nvt_in_raw.renderer.setShowGutter(true);\nvt_in_raw.setOption("
                   "\"showLineNumbers\", true);\nvt_in_raw.setOption(\"showPrintMargin\", "
                   "false);\nvt_in_raw.setOption(\"displayIndentGuides\", true);\nvt_in_raw.setOption(\"maxLines\", "
                   "\"Infinity\");\nvt_in_raw.session.setUseWrapMode(true);\nvt_in_raw.setOption("
                   "\"indentedSoftWrap\", true);\nvt_in_raw.renderer.setScrollMargin(8, 5);\n</script>",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    }
]