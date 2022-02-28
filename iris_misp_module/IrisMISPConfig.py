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
        "default": "",
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
]