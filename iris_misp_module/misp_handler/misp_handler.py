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
import logging as log
from jinja2 import Template

from iris_interface import IrisInterfaceStatus

from iris_misp_module.misp_handler.mispclient import MISPClient, MISPClientError

from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field


class MispHandler:
    def __init__(self, mod_config, logger):
        self.mod_config = mod_config
        self.http_proxy = self.mod_config.get('misp_http_proxy')
        self.https_proxy = self.mod_config.get('misp_https_proxy')
        self.misp = None
        self.log = logger

    def _load_misp_config(self):
        try:
            misp_config = json.loads(self.mod_config.get('misp_config'))
            return misp_config
        except json.JSONDecodeError as e:
            self.log.error(f"Error parsing MISP configuration: {e}")
            return None

    def load_misp_instance(self):
        """
        Initiates MISP(s) instance communication
        :returns MISPClient object
        """

        misp_config = self._load_misp_config()
        if misp_config is None:
            return None

        try:

            self.misp = {
                'type': misp_config.get('type', 'public'),
                'misp': MISPClient(url=misp_config.get('url', None),
                                   key=misp_config.get('key', None),
                                   ssl=misp_config.get('ssl', None),
                                   name=misp_config.get('name', None),
                                   proxies={'http': self.http_proxy, 'https': self.https_proxy})
            }

            return self.misp
        except MISPClientError as e:
            self.log.error(f"MISPClient Error initiating MISP instances {e}")
            return None
        except TypeError as te:
            self.log.error(f"Type Error initiating MISP instances {te}")
            return None

    def get_misp_instance(self):
        if len(self.misp) == 0:
            self.misp = self.load_misp_instance()

        return self.misp

    def gen_domain_report_from_template(self, html_template, misp_report) -> IrisInterfaceStatus:
        """
        Generates an HTML report for Domain, displayed as an attribute in the IOC

        :param html_template: A string representing the HTML template
        :param misp_report: The JSON report fetched with MISP API
        :return: IrisInterfaceStatus
        """
        template = Template(html_template)
        context = misp_report
        pre_render = dict({"results": []})

        # misp_results == dict({"name", "results", "url"})
        for misp_result in context:
            pre_render["results"].append(misp_result)

        try:

            rendered = template.render(pre_render)
            print(rendered)

        except Exception:
            print(traceback.format_exc())
            log.error(traceback.format_exc())
            return IrisInterfaceStatus.I2Error(traceback.format_exc())

        return IrisInterfaceStatus.I2Success(data=rendered)

    def gen_ip_report_from_template(self, html_template, misp_report) -> IrisInterfaceStatus:
        """
        Generates an HTML report for IP, displayed as an attribute in the IOC

        :param html_template: A string representing the HTML template
        :param misp_report: The JSON report fetched with MISP API
        :return: IrisInterfaceStatus
        """
        template = Template(html_template)
        context = misp_report
        pre_render = dict({"results": []})

        # misp_results == dict({"name", "results", "url"})
        for misp_result in context:
            pre_render["results"].append(misp_result)

        try:

            rendered = template.render(pre_render)
            print(rendered)

        except Exception:
            print(traceback.format_exc())
            log.error(traceback.format_exc())
            return IrisInterfaceStatus.I2Error(traceback.format_exc())

        return IrisInterfaceStatus.I2Success(data=rendered)

    def gen_hash_report_from_template(self, html_template, misp_report) -> IrisInterfaceStatus:
        """
        Generates an HTML report for Hash, displayed as an attribute in the IOC

        :param html_template: A string representing the HTML template
        :param misp_report: The JSON report fetched with VT API
        :return: IrisInterfaceStatus
        """
        template = Template(html_template)
        context = misp_report
        pre_render = dict({"results": []})

        # misp_results == dict({"name", "results", "url"})
        for misp_result in context:
            pre_render["results"].append(misp_result)

        try:

            rendered = template.render(pre_render)
            print(rendered)

        except Exception:
            print(traceback.format_exc())
            log.error(traceback.format_exc())
            return IrisInterfaceStatus.I2Error(traceback.format_exc())

        return IrisInterfaceStatus.I2Success(data=rendered)

    def handle_misp_domain(self, ioc):
        """
        Handles an IOC of type domain and adds MISP insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting domain report for {ioc.ioc_value}')
        report = self.misp.get("misp").search_domain(ioc.ioc_value)

        if self.mod_config.get('misp_report_as_attribute') is True:
            self.log.info('Adding new attribute MISP Domain Report to IOC')

            status = self.gen_domain_report_from_template(
                html_template=self.mod_config.get('misp_domain_report_template'),
                misp_report=report)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='MISP Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success()

    def handle_misp_ip(self, ioc):
        """
        Handles an IOC of type IP and adds MISP insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting IP report for {ioc.ioc_value}')
        report = self.misp.search_ip(ioc.ioc_value)

        if self.mod_config.get('misp_report_as_attribute') is True:
            self.log.info('Adding new attribute MISP IP Report to IOC')

            status = self.gen_ip_report_from_template(
                html_template=self.mod_config.get('misp_ip_report_template'),
                misp_report=report)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='MISP Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success("Successfully processed IP")

    def handle_misp_hash(self, ioc):
        """
        Handles an IOC of type hash and adds VT insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting hash report for {ioc.ioc_value}')
        report = self.misp.search_hash(ioc.ioc_value)

        if self.mod_config.get('misp_report_as_attribute') is True:
            self.log.info('Adding new attribute MISP IP Report to IOC')

            status = self.gen_hash_report_from_template(
                html_template=self.mod_config.get('misp_hash_report_template'),
                misp_report=report)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='MISP Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success("Successfully processed hash")
