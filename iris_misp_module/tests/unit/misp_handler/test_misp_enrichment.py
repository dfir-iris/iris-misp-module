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

"""Offline tests for the MISP to IRIS native IOC enrichment mapping.

The functions under test are pure: they only transform the report structure
returned by the MISP client and never reach the network.
"""

import json

import pytest

from iris_misp_module.misp_handler import enrichment

SOURCE_KEY = 'misp'


def _event(**overrides):
    """Return a cleaned MISP event as returned by the MISP client."""
    event = {
        'id': '1234',
        'info': 'Suspicious domain in phishing campaign',
        'date': '2026-01-10',
        'threat_level_id': '2',
        'Orgc': {'name': 'CERT Example'},
        'Tag': [
            {'name': 'tlp:amber'},
            {'name': 'admiralty-scale:source-reliability="a"'},
        ],
    }
    event.update(overrides)
    return event


def _instance(result, name='public', url='https://misp.example'):
    """Return one entry of the MISP client report."""
    return {'name': name, 'url': url, 'result': result}


def _payload(report):
    """Build the enrichment contribution and return its MISP payload."""
    contribution = enrichment.misp_build_enrichment(report)
    assert set(contribution) == {SOURCE_KEY}
    payload = contribution[SOURCE_KEY]
    json.dumps(payload)
    return payload


def test_single_matched_event_is_mapped():
    event = _event()
    report = [_instance([event])]

    payload = _payload(report)

    assert payload['match_status'] == 'matched'
    assert payload['event_count'] == 1
    assert payload['summary'] == (
        'Found 1 matching MISP event in 1 MISP instance; highest threat level: medium.')
    assert payload['threat_level'] == 'medium'
    assert payload['link'] == 'https://misp.example/events/view/1234'
    assert payload['event_ids'] == [1234]
    assert payload['organisations'] == ['CERT Example']
    assert payload['tags'] == ['tlp:amber', 'admiralty-scale:source-reliability="a"']
    assert payload['classifications'] == ['admiralty-scale:source-reliability="a"']
    assert payload['instances'] == [{
        'name': 'public',
        'url': 'https://misp.example',
        'event_count': 1,
    }]
    assert payload['events'] == [{
        'id': 1234,
        'info': 'Suspicious domain in phishing campaign',
        'date': '2026-01-10',
        'threat_level': 'medium',
        'organisation': 'CERT Example',
        'url': 'https://misp.example/events/view/1234',
        'tags': ['tlp:amber', 'admiralty-scale:source-reliability="a"'],
        'classifications': ['admiralty-scale:source-reliability="a"'],
        'related_events': [],
    }]
    assert 'verdict' not in payload
    # A MISP match is not a verdict, the raw report stays untouched.
    assert event['id'] == '1234'


def test_multiple_events_across_instances_are_mapped():
    report = [
        _instance(
            [_event(id='10', date='2026-01-01', threat_level_id='1',
                    Tag=[{'name': 'tlp:white'}])],
            name='one',
            url='https://misp-one.example'),
        _instance(
            [
                _event(id='20', date='2026-02-01', threat_level_id='3',
                       Orgc={'name': 'Other CERT'}),
                _event(id='30', date='2026-03-01', threat_level_id='2'),
            ],
            name='two',
            url='https://misp-two.example'),
    ]

    payload = _payload(report)

    assert payload['match_status'] == 'matched'
    assert payload['event_count'] == 3
    assert payload['summary'] == (
        'Found 3 matching MISP events in 2 MISP instances; highest threat level: high.')
    assert payload['threat_level'] == 'high'
    assert payload['link'] == 'https://misp-one.example/events/view/10'
    assert payload['event_ids'] == [10, 20, 30]
    assert payload['organisations'] == ['CERT Example', 'Other CERT']
    assert payload['tags'] == [
        'tlp:white',
        'tlp:amber',
        'admiralty-scale:source-reliability="a"',
    ]
    assert payload['classifications'] == ['admiralty-scale:source-reliability="a"']
    assert payload['instances'] == [
        {'name': 'one', 'url': 'https://misp-one.example', 'event_count': 1},
        {'name': 'two', 'url': 'https://misp-two.example', 'event_count': 2},
    ]
    assert len(payload['events']) == 3


@pytest.mark.parametrize(
    'threat_level_id, expected_level',
    [
        ('1', 'high'),
        (2, 'medium'),
        ('3', 'low'),
        (4, 'undefined'),
    ],
)
def test_threat_level_mapping(threat_level_id, expected_level):
    payload = _payload([_instance([_event(threat_level_id=threat_level_id)])])

    assert payload['threat_level'] == expected_level
    assert f'highest threat level: {expected_level}' in payload['summary']


def test_unknown_threat_level_id_falls_back_to_text_value():
    event = _event(threat_level_id='7', threat_level='High')

    payload = _payload([_instance([event])])

    assert payload['threat_level'] == 'high'
    assert payload['summary'] == (
        'Found 1 matching MISP event in 1 MISP instance; highest threat level: high.')


def test_unknown_threat_level_is_ignored_when_no_text_value_is_available():
    payload = _payload([_instance([_event(threat_level_id='7', threat_level=None)])])

    assert 'threat_level' not in payload
    assert payload['summary'] == 'Found 1 matching MISP event in 1 MISP instance.'


@pytest.mark.parametrize(
    'threat_level, expected_level',
    [
        (2, 'medium'),
        ('4', 'undefined'),
    ],
)
def test_numeric_threat_level_is_mapped(threat_level, expected_level):
    event = _event(threat_level_id=None, threat_level=threat_level)

    payload = _payload([_instance([event])])

    assert payload['threat_level'] == expected_level


def test_highest_threat_level_selects_most_severe_event():
    report = [_instance([
        _event(id='1', date='2026-03-01', threat_level_id='4'),
        _event(id='2', date='2026-01-01', threat_level_id='1'),
        _event(id='3', date='2026-02-01', threat_level_id='3'),
    ])]

    payload = _payload(report)

    assert payload['threat_level'] == 'high'
    assert payload['link'] == 'https://misp.example/events/view/2'
    assert payload['summary'].endswith('highest threat level: high.')


def test_primary_link_prefers_most_recent_event_at_highest_threat_level():
    report = [_instance([
        _event(id='5', date='2026-01-01', threat_level_id='1'),
        _event(id='6', date='2026-04-01', threat_level_id='1'),
    ])]

    payload = _payload(report)

    assert payload['link'] == 'https://misp.example/events/view/6'


@pytest.mark.parametrize(
    'instance_url',
    ['https://misp.example', 'https://misp.example/', 'https://misp.example///'],
)
def test_event_url_building_normalises_trailing_slashes(instance_url):
    payload = _payload([_instance([_event(id='77')], url=instance_url)])

    assert payload['link'] == 'https://misp.example/events/view/77'
    assert payload['events'][0]['url'] == 'https://misp.example/events/view/77'


def test_link_is_absent_without_instance_url():
    payload = _payload([_instance([_event()], url=None)])

    assert 'link' not in payload
    assert payload['instances'][0]['url'] is None
    assert payload['events'][0]['url'] is None


def test_related_events_are_mapped():
    event = _event(RelatedEvent=[
        {'Event': {'id': '99', 'info': 'Related event'}},
        {'id': '100', 'info': 'Second related event'},
        {'Event': {'id': '99', 'info': 'Related event (duplicate)'}},
        None,
        'not-a-dict',
    ])

    payload = _payload([_instance([event], url='https://misp.example/')])

    assert payload['events'][0]['related_events'] == [
        {'id': 99, 'info': 'Related event',
         'url': 'https://misp.example/events/view/99'},
        {'id': 100, 'info': 'Second related event',
         'url': 'https://misp.example/events/view/100'},
    ]


def test_related_events_are_normalised_in_cleaned_report_shape():
    # The MISP client cleans related events to {'info': ..., 'id': ...} dicts.
    event = _event(RelatedEvent=[
        {'info': 'Related event', 'id': '99'},
        {'info': None, 'id': 'bad-id'},
        'not-a-dict',
    ])

    payload = _payload([_instance([event])])

    related_events = payload['events'][0]['related_events']
    assert related_events == [
        {'id': 99, 'info': 'Related event',
         'url': 'https://misp.example/events/view/99'},
        {'id': None, 'info': None, 'url': None},
    ]


def test_tlp_tags_are_kept_but_not_classified():
    tags = [
        {'name': 'tlp:white'},
        {'name': 'TLP:RED'},
        {'name': '  tlp:amber  '},
        {'name': 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"'},
        {'name': 'admiralty-scale:source-reliability="a"'},
        {'name': 'simple-tag'},
        {'name': 'plain-string-tag'},
        {'name': 'admiralty-scale:source-reliability="a"'},
    ]
    event = _event(Tag=tags)

    payload = _payload([_instance([event])])

    assert payload['tags'] == [
        'tlp:white',
        'TLP:RED',
        'tlp:amber',
        'misp-galaxy:mitre-attack-pattern="Phishing - T1566"',
        'admiralty-scale:source-reliability="a"',
        'simple-tag',
        'plain-string-tag',
    ]
    assert payload['classifications'] == [
        'misp-galaxy:mitre-attack-pattern="Phishing - T1566"',
        'admiralty-scale:source-reliability="a"',
    ]


def test_plain_string_tags_are_supported():
    payload = _payload([_instance([_event(Tag=['first-tag', 'second-tag'])])])

    assert payload['tags'] == ['first-tag', 'second-tag']
    assert 'classifications' not in payload


def test_lists_are_bounded_and_deduplicated():
    events = []
    for index in range(30):
        events.append(_event(
            id=str(index + 1),
            date=f'2026-01-{index + 1:02d}',
            threat_level_id='4',
            Orgc={'name': f'CERT {index % 12}'},
            Tag=[
                {'name': 'tlp:white'},
                {'name': f'plain-tag-{index}'},
                {'name': f'admiralty-scale:reliability="{index}"'},
            ],
        ))

    payload = _payload([_instance(events)])

    assert payload['event_count'] == 30
    assert len(payload['events']) == 25
    assert payload['events_truncated'] is True
    assert len(payload['tags']) == 25
    assert len(set(payload['tags'])) == 25
    assert len(payload['classifications']) == 25
    assert len(set(payload['classifications'])) == 25
    assert payload['event_ids'] == list(range(1, 26))
    assert payload['organisations'] == [f'CERT {index}' for index in range(10)]
    assert payload['summary'] == (
        'Found 30 matching MISP events in 1 MISP instance; highest threat level: undefined.')


def test_events_payload_is_truncated_only_above_the_bound():
    events = [_event(id=str(index), Tag=[]) for index in range(1, 26)]

    payload = _payload([_instance(events)])
    assert len(payload['events']) == 25
    assert 'events_truncated' not in payload

    events.append(_event(id='26', Tag=[]))
    payload = _payload([_instance(events)])
    assert len(payload['events']) == 25
    assert payload['events_truncated'] is True
    assert payload['event_count'] == 26
    assert payload['event_ids'] == list(range(1, 26))


def test_duplicate_values_are_deduplicated():
    report = [
        _instance([_event(id='9', Tag=[{'name': 'duplicated-tag'}])],
                  name='first', url='https://one.example'),
        _instance([_event(id='9', Tag=[{'name': 'duplicated-tag'}])],
                  name='second', url='https://two.example'),
    ]

    payload = _payload(report)

    assert payload['event_ids'] == [9]
    assert payload['tags'] == ['duplicated-tag']
    assert 'classifications' not in payload
    assert payload['organisations'] == ['CERT Example']


def test_no_match_report_with_instances():
    payload = _payload([
        _instance([], name='first', url='https://one.example'),
        _instance([], name='second', url='https://two.example'),
    ])

    assert payload['match_status'] == 'no-match'
    assert payload['event_count'] == 0
    assert payload['summary'] == (
        'No matching MISP events found in 2 configured MISP instances.')
    assert 'events' not in payload
    assert 'link' not in payload
    assert 'event_ids' not in payload
    assert 'threat_level' not in payload
    assert payload['instances'] == [
        {'name': 'first', 'url': 'https://one.example', 'event_count': 0},
        {'name': 'second', 'url': 'https://two.example', 'event_count': 0},
    ]


def test_no_match_report_with_single_instance():
    payload = _payload([_instance([])])

    assert payload['match_status'] == 'no-match'
    assert payload['summary'] == (
        'No matching MISP events found in 1 configured MISP instance.')
    assert 'instances' in payload


def test_summary_counts_only_instances_with_matches():
    payload = _payload([
        _instance([], name='empty', url='https://one.example'),
        _instance([_event()], name='hit', url='https://two.example'),
    ])

    assert payload['event_count'] == 1
    assert payload['summary'] == (
        'Found 1 matching MISP event in 1 MISP instance; highest threat level: medium.')
    assert len(payload['instances']) == 2


def test_empty_report_is_no_match():
    payload = _payload([])
    assert payload['match_status'] == 'no-match'
    assert payload['event_count'] == 0
    assert payload['summary'] == 'No matching MISP events found.'
    assert 'instances' not in payload
    assert 'events' not in payload


@pytest.mark.parametrize('report', [None, {}, 'report', 42, (), ['not-a-dict', 7]])
def test_malformed_report_is_treated_as_no_match(report):
    payload = _payload(report)

    assert payload['match_status'] == 'no-match'
    assert payload['event_count'] == 0
    assert payload['summary'] == 'No matching MISP events found.'
    assert 'instances' not in payload
    assert 'events' not in payload


def test_malformed_report_entries_are_skipped():
    report = [
        None,
        'not-an-entry',
        42,
        {'name': 'no-results', 'url': 'https://one.example',
         'result': 'not-a-list'},
        {'name': 'junk-results', 'url': 'https://two.example',
         'result': [None, 'junk', 7]},
        {'name': 'matched', 'url': 'https://three.example',
         'result': [_event(id='55'), None]},
    ]

    payload = _payload(report)

    assert payload['match_status'] == 'matched'
    assert payload['event_count'] == 1
    assert payload['link'] == 'https://three.example/events/view/55'
    assert payload['instances'] == [
        {'name': 'no-results', 'url': 'https://one.example', 'event_count': 0},
        {'name': 'junk-results', 'url': 'https://two.example', 'event_count': 0},
        {'name': 'matched', 'url': 'https://three.example', 'event_count': 1},
    ]
    assert payload['summary'] == (
        'Found 1 matching MISP event in 1 MISP instance; highest threat level: medium.')


def test_malformed_event_fields_are_normalised():
    event = {
        'id': True,
        'info': None,
        'date': 20260115,
        'threat_level_id': 'not-a-number',
        'Orgc': ['not', 'a', 'dict'],
        'Tag': 'not-a-list',
        'RelatedEvent': 'not-a-list',
    }

    payload = _payload([_instance([event, None])])

    assert payload['match_status'] == 'matched'
    assert payload['event_count'] == 1
    assert payload['summary'] == 'Found 1 matching MISP event in 1 MISP instance.'
    assert payload['events'] == [{
        'id': None,
        'info': None,
        'date': '20260115',
        'threat_level': None,
        'organisation': None,
        'url': None,
        'tags': [],
        'classifications': [],
        'related_events': [],
    }]
    assert 'link' not in payload
    assert 'event_ids' not in payload
    assert 'threat_level' not in payload
    assert 'tags' not in payload


class TestMispMergeEnrichment:

    def test_preserves_other_sources_and_replaces_only_misp(self):
        existing = {
            'virustotal': {'verdict': 'harmless', 'score': 0},
            'misp': {'match_status': 'stale'},
        }
        contribution = {SOURCE_KEY: {'match_status': 'matched'}}

        merged = enrichment.misp_merge_enrichment(existing, contribution)

        assert merged == {
            'virustotal': {'verdict': 'harmless', 'score': 0},
            'misp': {'match_status': 'matched'},
        }
        # The source dictionary is copied, not mutated.
        assert existing['misp'] == {'match_status': 'stale'}

    def test_none_existing_enrichment_is_replaced(self):
        contribution = {SOURCE_KEY: {'match_status': 'matched'}}

        merged = enrichment.misp_merge_enrichment(None, contribution)

        assert merged == contribution

    @pytest.mark.parametrize('existing', [[], 'legacy', 42, ('tupled',), True])
    def test_non_mapping_existing_enrichment_is_replaced(self, existing):
        contribution = {SOURCE_KEY: {'match_status': 'matched'}}

        merged = enrichment.misp_merge_enrichment(existing, contribution)

        assert merged == contribution

    def test_empty_existing_enrichment_is_completed(self):
        merged = enrichment.misp_merge_enrichment(
            {},
            enrichment.misp_build_enrichment([_instance([_event()])]))

        assert merged.keys() == {SOURCE_KEY}
        assert merged[SOURCE_KEY]['match_status'] == 'matched'

    def test_merge_with_built_contribution_keeps_other_sources(self):
        existing = {'some-other-module': {'summary': 'kept intact'}}
        contribution = enrichment.misp_build_enrichment([_instance([_event()])])

        merged = enrichment.misp_merge_enrichment(existing, contribution)

        assert merged['some-other-module'] == {'summary': 'kept intact'}
        assert merged[SOURCE_KEY]['event_count'] == 1


class TestMispMergeReports:

    def test_merges_reports_for_the_same_instance(self):
        domain_event = _event(id='10')
        ip_event = _event(id='20')
        domain_report = [_instance([domain_event], name='public',
                                   url='https://misp.example')]
        ip_report = [_instance([ip_event], name='public',
                               url='https://misp.example')]

        merged = enrichment.misp_merge_reports([domain_report, ip_report])

        assert merged == [{
            'name': 'public',
            'url': 'https://misp.example',
            'result': [domain_event, ip_event],
        }]

    def test_distinct_instances_stay_distinct(self):
        report = [
            _instance([_event(id='10')], name='public',
                      url='https://misp-one.example'),
            _instance([_event(id='20')], name='private',
                      url='https://misp-two.example'),
        ]

        merged = enrichment.misp_merge_reports([report])

        assert len(merged) == 2
        assert [entry['name'] for entry in merged] == ['public', 'private']
        assert [entry['url'] for entry in merged] == [
            'https://misp-one.example',
            'https://misp-two.example',
        ]

    def test_same_name_with_different_url_stays_distinct(self):
        report = [
            _instance([_event(id='10')], name='public',
                      url='https://misp-one.example'),
            _instance([_event(id='20')], name='public',
                      url='https://misp-two.example'),
        ]

        merged = enrichment.misp_merge_reports([report])

        assert len(merged) == 2
        assert [entry['result'][0]['id'] for entry in merged] == ['10', '20']

    def test_non_list_reports_are_skipped(self):
        entry = _instance([_event(id='10')])

        merged = enrichment.misp_merge_reports(
            [None, {}, 'report', 42, (entry,), [entry]])

        assert merged == [entry]

    def test_malformed_entries_are_skipped(self):
        merged = enrichment.misp_merge_reports([[
            None,
            'not-an-entry',
            {'name': 'no-results', 'url': 'https://one.example',
             'result': 'not-a-list'},
            {'name': 'matched', 'url': 'https://two.example',
             'result': [_event(id='55'), None]},
        ]])

        assert merged == [
            {'name': 'no-results', 'url': 'https://one.example', 'result': []},
            {'name': 'matched', 'url': 'https://two.example',
             'result': [_event(id='55'), None]},
        ]

    def test_empty_reports_are_merged_to_nothing(self):
        assert enrichment.misp_merge_reports([]) == []
        assert enrichment.misp_merge_reports([[], []]) == []

    def test_merged_reports_build_multi_event_enrichment(self):
        merged = enrichment.misp_merge_reports([
            [_instance([_event(id='10', date='2026-01-01', threat_level_id='2')])],
            [_instance([_event(id='20', date='2026-02-01', threat_level_id='1')])],
        ])

        payload = _payload(merged)

        assert payload['match_status'] == 'matched'
        assert payload['event_count'] == 2
        assert payload['event_ids'] == [10, 20]
        assert len(payload['instances']) == 1
        assert payload['instances'][0]['event_count'] == 2

    def test_duplicate_events_are_deduplicated_per_instance(self):
        domain_report = [_instance([_event(id='10')])]
        ip_report = [_instance([_event(id=10), _event(id='11')])]

        merged = enrichment.misp_merge_reports([domain_report, ip_report])

        assert len(merged) == 1
        assert [event['id'] for event in merged[0]['result']] == ['10', '11']
        payload = _payload(merged)
        assert payload['event_count'] == 2
        assert payload['event_ids'] == [10, 11]
