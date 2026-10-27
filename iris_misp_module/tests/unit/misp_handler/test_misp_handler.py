#  IRIS MISP Module Source Code
#  Copyright (C) 2026 - DFIR-IRIS
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

"""Offline tests for the IrisMISP handler and its native IOC enrichment.

The IRIS backend ``app.datamgmt`` modules are stubbed in ``conftest.py`` and
the pymisp client is always mocked here, so the suite runs without network
access or an IRIS deployment.
"""

import json
import logging
from unittest import mock

import pytest

from iris_misp_module.misp_handler import mispclient
from iris_misp_module.misp_handler.misp_handler import MispHandler

EXPANDED_PYMISP = 'iris_misp_module.misp_handler.mispclient.pymisp.ExpandedPyMISP'
ADD_TAB_ATTRIBUTE = 'iris_misp_module.misp_handler.misp_handler.add_tab_attribute_field'
REPORT_TEMPLATE = '<div>{{ results|length }}</div>'


def _module_config(**overrides):
    config = {
        'misp_config': json.dumps({
            'name': 'public',
            'type': 'public',
            'url': ['https://misp.example'],
            'key': ['api-key'],
            'ssl': [False],
        }),
        'misp_http_proxy': None,
        'misp_https_proxy': None,
        'misp_report_as_attribute': True,
        'misp_domain_report_template': REPORT_TEMPLATE,
        'misp_ip_report_template': REPORT_TEMPLATE,
    }
    config.update(overrides)
    return config


def _handler(**overrides):
    return MispHandler(mod_config=_module_config(**overrides),
                       logger=logging.getLogger('iris_misp_module.tests'))


def _instance(result, name='public', url='https://misp.example'):
    return {'name': name, 'url': url, 'result': result}


def _event(**overrides):
    event = {
        'id': '1234',
        'info': 'Suspicious domain in phishing campaign',
        'date': '2026-01-10',
        'threat_level_id': '2',
        'Orgc': {'name': 'CERT Example'},
        'Tag': [{'name': 'tlp:amber'}],
    }
    event.update(overrides)
    return event


class FakeIoc:
    """Minimal stand-in for the IRIS IOC model received by the hooks."""

    __tablename__ = 'ioc'

    def __init__(self, ioc_value='evil.example', ioc_tags='', ioc_enrichment=None):
        self.ioc_value = ioc_value
        self.ioc_tags = ioc_tags
        self.ioc_enrichment = ioc_enrichment


def test_load_misp_config_returns_parsed_configuration():
    handler = _handler()

    expected = {
        'name': 'public',
        'type': 'public',
        'url': ['https://misp.example'],
        'key': ['api-key'],
        'ssl': [False],
    }
    assert handler._load_misp_config() == expected


def test_load_misp_config_returns_none_for_invalid_json():
    handler = _handler(misp_config='{"name": "public", "url": [}')

    assert handler._load_misp_config() is None


@pytest.mark.parametrize('misp_config', ['[]', '[{"name": "x"}]', '"public"', '42'])
def test_load_misp_config_returns_none_for_non_object_json(misp_config):
    handler = _handler(misp_config=misp_config)

    assert handler._load_misp_config() is None

    with mock.patch(EXPANDED_PYMISP) as expanded_pymisp:
        assert handler.load_misp_instance() is None
    expanded_pymisp.assert_not_called()


def test_load_misp_instance_creates_misp_client():
    handler = _handler()

    with mock.patch(EXPANDED_PYMISP) as expanded_pymisp:
        instance = handler.load_misp_instance()

    assert instance is not None
    assert instance['type'] == 'public'
    assert isinstance(instance['misp'], mispclient.MISPClient)
    expanded_pymisp.assert_called_once_with(
        url='https://misp.example',
        key='api-key',
        ssl=False,
        proxies={'http': None, 'https': None},
    )


def test_load_misp_instance_returns_none_on_client_error():
    handler = _handler()

    with mock.patch(EXPANDED_PYMISP, side_effect=mispclient.MISPClientError('unreachable')):
        assert handler.load_misp_instance() is None


def test_load_misp_instance_returns_none_on_type_error():
    handler = _handler()

    with mock.patch(EXPANDED_PYMISP, side_effect=TypeError('invalid configuration')):
        assert handler.load_misp_instance() is None


def test_handle_misp_domain_runs_offline_end_to_end():
    handler = _handler()

    with mock.patch(EXPANDED_PYMISP):
        handler.load_misp_instance()

    connection = handler.misp['misp'].misp_connections[0]
    connection.root_url = 'https://misp.example'
    connection.search.return_value = [{'Event': _event()}]

    ioc = FakeIoc(ioc_value='evil.example', ioc_tags='initial-tag')

    with mock.patch(ADD_TAB_ATTRIBUTE) as add_attribute:
        status = handler.handle_misp_domain(ioc)

    assert status.is_success()
    assert ioc.ioc_enrichment['misp']['match_status'] == 'matched'
    assert ioc.ioc_enrichment['misp']['link'] == 'https://misp.example/events/view/1234'
    assert ioc.ioc_enrichment['misp']['threat_level'] == 'medium'
    assert 'misp:hit' in ioc.ioc_tags
    add_attribute.assert_called_once()
    assert connection.search.call_args.kwargs['value'] == 'evil.example'
    assert 'domain' in connection.search.call_args.kwargs['type_attribute']


def test_populate_enrichment_is_enabled_by_default_when_option_is_absent():
    handler = _handler()

    assert handler._populate_enrichment_enabled() is True


@pytest.mark.parametrize(
    'configured, expected',
    [
        (True, True),
        ('yes', True),
        (False, False),
        (0, False),
        ('', False),
    ],
)
def test_populate_enrichment_option_is_honoured(configured, expected):
    handler = _handler(misp_populate_enrichment=configured)

    assert handler._populate_enrichment_enabled() is expected


def test_handle_misp_report_populates_enrichment_by_default():
    handler = _handler()
    ioc = FakeIoc(ioc_tags='initial-tag')

    with mock.patch(ADD_TAB_ATTRIBUTE) as add_attribute:
        status = handler._handle_misp_report(ioc, [_instance([_event()])], REPORT_TEMPLATE)

    assert status.is_success()
    assert ioc.ioc_enrichment['misp']['match_status'] == 'matched'
    assert ioc.ioc_enrichment['misp']['event_count'] == 1
    assert ioc.ioc_enrichment['misp']['summary'] == (
        'Found 1 matching MISP event in 1 MISP instance; highest threat level: medium.')
    assert 'misp:hit' in ioc.ioc_tags
    add_attribute.assert_called_once()
    call = add_attribute.call_args
    assert call.args[0] is ioc
    assert call.kwargs['tab_name'] == 'MISP Report'
    assert call.kwargs['field_name'] == 'HTML report'
    assert call.kwargs['field_type'] == 'html'
    assert call.kwargs['field_value'] == '<div>1</div>'


def test_handle_misp_report_creates_enrichment_when_existing_is_none():
    handler = _handler()
    ioc = FakeIoc(ioc_enrichment=None)

    with mock.patch(ADD_TAB_ATTRIBUTE):
        status = handler._handle_misp_report(ioc, [_instance([_event()])], REPORT_TEMPLATE)

    assert status.is_success()
    assert isinstance(ioc.ioc_enrichment, dict)
    assert ioc.ioc_enrichment['misp']['match_status'] == 'matched'


def test_handle_misp_report_replaces_non_mapping_existing_enrichment():
    handler = _handler()
    ioc = FakeIoc(ioc_enrichment=['legacy data'])

    with mock.patch(ADD_TAB_ATTRIBUTE):
        status = handler._handle_misp_report(ioc, [_instance([_event()])], REPORT_TEMPLATE)

    assert status.is_success()
    assert isinstance(ioc.ioc_enrichment, dict)
    assert set(ioc.ioc_enrichment) == {'misp'}


def test_disabled_option_keeps_existing_enrichment_and_writes_attribute():
    handler = _handler(misp_populate_enrichment=False)
    existing = {'virustotal': {'verdict': 'harmless'}}
    ioc = FakeIoc(ioc_tags='', ioc_enrichment=existing)

    with mock.patch(ADD_TAB_ATTRIBUTE) as add_attribute:
        status = handler._handle_misp_report(ioc, [_instance([_event()])], REPORT_TEMPLATE)

    assert status.is_success()
    assert ioc.ioc_enrichment is existing
    assert ioc.ioc_enrichment == {'virustotal': {'verdict': 'harmless'}}
    assert 'misp:hit' in ioc.ioc_tags
    add_attribute.assert_called_once()


def test_existing_enrichment_sources_are_preserved():
    handler = _handler()
    existing = {
        'virustotal': {'verdict': 'harmless'},
        'misp': {'match_status': 'stale'},
    }
    ioc = FakeIoc(ioc_enrichment=existing)

    with mock.patch(ADD_TAB_ATTRIBUTE):
        status = handler._handle_misp_report(ioc, [_instance([_event()])], REPORT_TEMPLATE)

    assert status.is_success()
    assert ioc.ioc_enrichment['virustotal'] == {'verdict': 'harmless'}
    assert ioc.ioc_enrichment['misp']['match_status'] == 'matched'
    assert existing['misp'] == {'match_status': 'stale'}


def test_template_render_error_still_writes_enrichment_and_returns_error():
    handler = _handler()
    ioc = FakeIoc(ioc_tags='initial-tag')

    with mock.patch(ADD_TAB_ATTRIBUTE) as add_attribute:
        status = handler._handle_misp_report(ioc, [_instance([_event()])], '{{ 1 / 0 }}')

    assert status.is_failure()
    add_attribute.assert_not_called()
    assert ioc.ioc_enrichment['misp']['match_status'] == 'matched'
    assert ioc.ioc_tags == 'initial-tag'


def test_no_hit_report_sets_no_match_and_removes_hit_tag():
    handler = _handler()
    ioc = FakeIoc(ioc_tags='initial-tag,misp:hit')

    with mock.patch(ADD_TAB_ATTRIBUTE):
        status = handler._handle_misp_report(ioc, [_instance([])], REPORT_TEMPLATE)

    assert status.is_success()
    assert ioc.ioc_enrichment['misp']['match_status'] == 'no-match'
    assert ioc.ioc_enrichment['misp']['event_count'] == 0
    assert 'misp:hit' not in ioc.ioc_tags


def test_disabled_attribute_still_populates_enrichment():
    handler = _handler(misp_report_as_attribute=False)
    ioc = FakeIoc()

    with mock.patch(ADD_TAB_ATTRIBUTE) as add_attribute:
        status = handler._handle_misp_report(ioc, [_instance([_event()])], REPORT_TEMPLATE)

    assert status.is_success()
    assert ioc.ioc_enrichment['misp']['match_status'] == 'matched'
    assert 'misp:hit' in ioc.ioc_tags
    add_attribute.assert_not_called()


def test_invalid_template_returns_error_and_still_writes_enrichment():
    handler = _handler()
    ioc = FakeIoc(ioc_tags='initial-tag')

    with mock.patch(ADD_TAB_ATTRIBUTE) as add_attribute:
        status = handler._handle_misp_report(ioc, [_instance([_event()])], '{{ results|nofilter }}')

    assert status.is_failure()
    add_attribute.assert_not_called()
    assert ioc.ioc_enrichment['misp']['match_status'] == 'matched'
    assert ioc.ioc_tags == 'initial-tag'


@pytest.mark.parametrize('report', [None, {}, 'report', 42])
def test_non_list_report_is_treated_as_empty(report):
    handler = _handler()
    ioc = FakeIoc(ioc_tags='initial-tag')

    with mock.patch(ADD_TAB_ATTRIBUTE) as add_attribute:
        status = handler._handle_misp_report(ioc, report, REPORT_TEMPLATE)

    assert status.is_success()
    assert ioc.ioc_enrichment['misp']['match_status'] == 'no-match'
    assert ioc.ioc_enrichment['misp']['event_count'] == 0
    assert ioc.ioc_tags == 'initial-tag'
    add_attribute.assert_called_once()
    assert add_attribute.call_args.kwargs['field_value'] == '<div>0</div>'


def test_handle_misp_domain_ip_builds_one_merged_enrichment():
    handler = _handler(
        misp_domain_report_template='<div>domain {{ results|length }}</div>',
        misp_ip_report_template='<div>ip {{ results|length }}</div>',
    )

    with mock.patch(EXPANDED_PYMISP):
        handler.load_misp_instance()

    connection = handler.misp['misp'].misp_connections[0]
    connection.root_url = 'https://misp.example'
    connection.search.side_effect = [
        [{'Event': _event(id='1001')}],
        [{'Event': _event(id='2002', threat_level_id='1',
                          Tag=[{'name': 'tlp:red'}])}],
    ]

    ioc = FakeIoc(ioc_value='evil.example|10.0.0.1', ioc_tags='initial-tag')

    with mock.patch(ADD_TAB_ATTRIBUTE) as add_attribute:
        status = handler.handle_misp_domain_ip(ioc)

    assert status.is_success()
    misp_enrichment = ioc.ioc_enrichment['misp']
    assert misp_enrichment['event_count'] == 2
    assert misp_enrichment['event_ids'] == [1001, 2002]
    assert len(misp_enrichment['instances']) == 1
    assert misp_enrichment['instances'][0]['event_count'] == 2
    assert len(misp_enrichment['events']) == 2
    search_calls = connection.search.call_args_list
    assert len(search_calls) == 2
    domain_types = search_calls[0].kwargs['type_attribute']
    ip_types = search_calls[1].kwargs['type_attribute']
    assert search_calls[0].kwargs['value'] == 'evil.example'
    assert search_calls[1].kwargs['value'] == '10.0.0.1'
    # The domain half is searched with domain types, the IP half with IP types.
    assert 'domain' in domain_types
    assert 'ip-src' not in domain_types
    assert 'ip-dst' not in domain_types
    assert 'ip-src' in ip_types
    assert 'ip-dst' in ip_types
    assert domain_types != ip_types
    # Both legacy HTML reports are still written.
    assert add_attribute.call_count == 2
    rendered_reports = [
        call.kwargs['field_value'] for call in add_attribute.call_args_list
    ]
    assert rendered_reports == ['<div>domain 1</div>', '<div>ip 1</div>']
