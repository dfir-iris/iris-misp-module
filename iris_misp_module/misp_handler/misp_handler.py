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
import logging as log
import traceback

import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field
from iris_interface import IrisInterfaceStatus
from jinja2 import Template

from iris_misp_module.misp_handler.mispclient import MISPClient, MISPClientError


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

    def gen_report_from_template(self, html_template, misp_report) -> IrisInterfaceStatus:
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

        except Exception:
            print(traceback.format_exc())
            log.error(traceback.format_exc())
            return IrisInterfaceStatus.I2Error(traceback.format_exc())

        return IrisInterfaceStatus.I2Success(data=rendered)

    def _handle_misp_report(self, ioc, report, html_report_template):
        """
        Handle the MISP report response, adds the report as attribute and attaches a tag on hit
        """

        if self.mod_config.get('misp_report_as_attribute') is True:
            self.log.info('Adding new attribute MISP Report to IOC')

            status = self.gen_report_from_template(
                html_template=html_report_template,
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

        # Check if we have any hits, and add/remove tag
        hits = [r for r in report if r.get('result')]
        if len(hits) > 0:
            if "misp:hit" not in ioc.ioc_tags:
                ioc.ioc_tags = f"{ioc.ioc_tags},misp:hit"
        else:
            ioc.ioc_tags = ioc.ioc_tags.replace("misp:hit", "")

        return InterfaceStatus.I2Success("Successfully processed IOC")

    def handle_misp_domain(self, ioc):
        """
        Handles an IOC of type domain and adds MISP insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting domain report for {ioc.ioc_value}')
        report = self.misp.get("misp").search_domain(ioc.ioc_value)

        return self._handle_misp_report(ioc, report, self.mod_config.get('misp_domain_report_template'))

    def handle_misp_ip(self, ioc):
        """
        Handles an IOC of type IP and adds MISP insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting IP report for {ioc.ioc_value}')
        report = self.misp.get("misp").search_ip(ioc.ioc_value)

        return self._handle_misp_report(ioc, report, self.mod_config.get('misp_ip_report_template'))

    def handle_misp_hash(self, ioc):
        """
        Handles an IOC of type hash and adds VT insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting hash report for {ioc.ioc_value}')
        report = self.misp.get("misp").search_hash(ioc.ioc_value)

        return self._handle_misp_report(ioc, report, self.mod_config.get('misp_hash_report_template'))

    def handle_misp_domain_ip(self, ioc):
        """
        Handles an IOC of type domain|ip and adds MISP insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting domain|ip report for {ioc.ioc_value}')
        domain, ip = ioc.ioc_value.split('|')
        domain_report = self.misp.get("misp").search_domain(domain)
        ip_report = self.misp.get("misp").search_domain(ip)

        domain_result = self._handle_misp_report(ioc, domain_report, self.mod_config.get('misp_domain_report_template'))
        if not domain_result.is_success():
            return domain_result

        ip_result = self._handle_misp_report(ioc, ip_report, self.mod_config.get('misp_ip_report_template'))

        return ip_result

    def handle_misp_ja3(self, ioc):
        """
        Handles an IOC of type JA3 and adds MISP insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        self.log.info(f'Getting JA3 report for {ioc.ioc_value}')
        report = self.misp.get("misp").search_ja3(ioc.ioc_value)

        return self._handle_misp_report(ioc, report, self.mod_config.get('misp_ja3_report_template'))
