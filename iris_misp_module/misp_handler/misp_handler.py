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
import json
import traceback

from iris_misp_module.misp_handler.mispclient import MISPClient, MISPClientError

from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field


class MispHandler():
    def __init__(self, mod_config, logger):
        self.mod_config = mod_config
        self.http_proxy = self.mod_config.get('misp_http_proxy')
        self.https_proxy = self.mod_config.get('misp_https_proxy')
        self.misp = self.get_misp_instance()
        self.log = logger

    def get_misp_instance(self):
        """
        """
        try:
            misp_config = json.loads(self.mod_config.get('misp_config'))
        except json.JSONDecodeError as e:
            self.log.error(f"Error parsing MISP configuration: {e}")
            return None

        try:

            return MISPClient(url=misp_config.get('config.url', None, 'No MISP url given.'),
                              key=misp_config.get('config.key', None, 'No MISP api key given.'),
                              ssl=misp_config.get('config.ssl', None, 'No MISP ssl given.'),
                              name=misp_config.get('config.name', None, 'No MISP name given.'),
                              proxies={'http': self.http_proxy, 'https': self.https_proxy})
        except MISPClientError as e:
            self.log.error(f"MISPClient Error initiating MISP instances {e}")
        except TypeError as te:
            self.log.error(f"Type Error initiating MISP instances {te}")

    def handle_misp_domain(self, ioc):
        """
        Handles an IOC of type domain and adds MISP insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting domain report for {ioc.ioc_value}')
        report = self.misp.search_domain(ioc.ioc_value)


        return InterfaceStatus.I2Success()

    def handle_misp_ip(self, ioc):
        """
        Handles an IOC of type IP and adds MISP insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting IP report for {ioc.ioc_value}')
        report = self.misp.search_ip(ioc.ioc_value)

        status = self._validate_report(report)


        return InterfaceStatus.I2Success("Successfully processed IP")

    def handle_misp_hash(self, ioc):
        """
        Handles an IOC of type hash and adds VT insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting hash report for {ioc.ioc_value}')
        report = self.misp.search_hash(ioc.ioc_value)


        return InterfaceStatus.I2Success("Successfully processed hash")
