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

"""Normalisation of MISP search results into the IRIS native IOC enrichment.

Since IRIS 3, the IOC details view renders ``ioc.ioc_enrichment`` (a JSONB
column) as one block per enrichment source. A module running a hook receives
the IOC as a SQLAlchemy object attached to the session, so it can write that
column directly: the backend commits the changes made by the module once the
hook handler returns.

This module turns the list of raw MISP search results returned by
:class:`iris_misp_module.misp_handler.mispclient.MISPClient` into a payload
under the ``misp`` source key. The payload deliberately carries no ``verdict``:
a MISP match is not, by itself, a malicious verdict, and the analyst-facing
verdict is left to modules that can actually classify the IOC. The MISP threat
level and tags are reported as findings instead.

The legacy HTML report written to the IOC custom attributes is untouched: the
two representations answer different needs, and the HTML report keeps the full
raw JSON of the MISP results.
"""

SOURCE_KEY = 'misp'

# MISP threat levels, see https://www.misp-project.org/taxonomies/ and the
# threat_level_id attribute exposed on MISP events.
THREAT_LEVELS = {
    '1': 'high',
    '2': 'medium',
    '3': 'low',
    '4': 'undefined',
}

# Highest threat level first, used to pick the most relevant event for the
# "Open report" link.
_THREAT_LEVEL_RANK = {
    'high': 3,
    'medium': 2,
    'low': 1,
    'undefined': 0,
}

# Bounds for the values that are rendered as a single line by the enrichment
# panel. The complete data remains available in the raw JSON view through the
# ``instances`` and ``events`` keys.
_MAX_TAGS = 25
_MAX_CLASSIFICATIONS = 25
_MAX_EVENT_IDS = 25
_MAX_ORGANISATIONS = 10
_MAX_EVENTS = 25

# Tag namespaces which do not express a classification. TLP is a sharing
# marking, not a classification of the observed event.
_NON_CLASSIFICATION_NAMESPACES = ('tlp',)


def _string(value):
    """Return a stripped string for a scalar value, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _integer(value):
    """Return an int for an int-like value, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except (TypeError, ValueError):
            return None
    return None


def _deduplicate(values):
    """Deduplicate values while preserving the original order."""
    unique = []
    for value in values:
        if value not in unique:
            unique.append(value)
    return unique


def _bounded(values, limit):
    """Deduplicate values and keep at most ``limit`` of them."""
    return _deduplicate(values)[:limit]


def _plural(count, singular, plural):
    """Pick the singular or plural form for ``count``."""
    return singular if count == 1 else plural


def _event_id(event):
    """Return the MISP event identifier, as an int when possible."""
    return _integer(event.get('id'))


def _event_info(event):
    """Return the MISP event title."""
    return _string(event.get('info'))


def _event_date(event):
    """Return the MISP event date."""
    return _string(event.get('date'))


def _event_threat_level(event):
    """Return the human-readable threat level of a MISP event, or None."""
    threat_level_id = _integer(event.get('threat_level_id'))
    if threat_level_id is not None:
        threat_level = THREAT_LEVELS.get(str(threat_level_id))
        if threat_level:
            return threat_level
    threat_level = _string(event.get('threat_level'))
    if threat_level:
        mapped_threat_level = THREAT_LEVELS.get(threat_level)
        if mapped_threat_level:
            return mapped_threat_level
        return threat_level.lower()
    return None


def _event_related_events(event, instance_url):
    """Return the related MISP events of an event, or an empty list."""
    related_events = event.get('RelatedEvent')
    if not isinstance(related_events, list):
        return []
    normalised = []
    seen_ids = set()
    for related_event in related_events:
        if not isinstance(related_event, dict):
            continue
        # The MISP client strips related events to {'id', 'info'}, but the
        # raw MISP response nests the event under an 'Event' key.
        if isinstance(related_event.get('Event'), dict):
            related_event = related_event['Event']
        related_event_id = _integer(related_event.get('id'))
        if related_event_id is not None:
            if related_event_id in seen_ids:
                continue
            seen_ids.add(related_event_id)
        normalised.append({
            'id': related_event_id,
            'info': _string(related_event.get('info')),
            'url': _event_url(instance_url, related_event_id),
        })
    return normalised


def _event_organisation(event):
    """Return the name of the organisation which published a MISP event."""
    for key in ('Orgc', 'Org'):
        organisation = event.get(key)
        if isinstance(organisation, dict):
            name = _string(organisation.get('name'))
            if name:
                return name
        name = _string(organisation)
        if name:
            return name
    return None


def _event_tags(event):
    """Return the names of the tags attached to a MISP event."""
    tags = event.get('Tag')
    if not isinstance(tags, list):
        return []
    names = []
    for tag in tags:
        if isinstance(tag, dict):
            name = _string(tag.get('name'))
        else:
            name = _string(tag)
        if name:
            names.append(name)
    return _deduplicate(names)


def _event_classifications(tags):
    """Return the taxonomy tags of a MISP event that express a classification."""
    classifications = []
    for name in tags:
        if ':' not in name:
            continue
        namespace = name.split(':', 1)[0].strip().lower()
        if namespace in _NON_CLASSIFICATION_NAMESPACES:
            continue
        classifications.append(name)
    return _deduplicate(classifications)


def _event_url(instance_url, event_id):
    """Return the MISP event URL for an instance, or None."""
    base_url = _string(instance_url)
    if not base_url or event_id is None:
        return None
    return f"{base_url.rstrip('/')}/events/view/{event_id}"


def _normalise_event(event, instance_url):
    """Return the enrichment representation of a single MISP event."""
    event_id = _event_id(event)
    tags = _event_tags(event)
    return {
        'id': event_id,
        'info': _event_info(event),
        'date': _event_date(event),
        'threat_level': _event_threat_level(event),
        'organisation': _event_organisation(event),
        'url': _event_url(instance_url, event_id),
        'tags': tags,
        'classifications': _event_classifications(tags),
        'related_events': _event_related_events(event, instance_url),
    }


def _collect_events(report):
    """Collect the normalised events and the queried instances from a report.

    ``report`` is the list returned by the MISP client: one entry per
    configured instance, each with the instance name, URL and the cleaned
    MISP events. Malformed entries are skipped rather than raising, so a
    partial MISP response still produces a useful enrichment.
    """
    events = []
    instances = []
    if not isinstance(report, list):
        return events, instances

    for entry in report:
        if not isinstance(entry, dict):
            continue
        instance_url = _string(entry.get('url'))
        instance_name = _string(entry.get('name'))
        results = entry.get('result')
        if not isinstance(results, list):
            results = []
        instance_events = []
        for result in results:
            if not isinstance(result, dict):
                continue
            instance_events.append(_normalise_event(result, instance_url))
        instances.append({
            'name': instance_name,
            'url': instance_url,
            'event_count': len(instance_events),
        })
        events.extend(instance_events)

    return events, instances


def _highest_threat_level(events):
    """Return the highest threat level found in a list of events, or None."""
    highest_level = None
    highest_rank = -1
    for event in events:
        level = event.get('threat_level')
        rank = _THREAT_LEVEL_RANK.get(level, -1)
        if rank > highest_rank:
            highest_level = level
            highest_rank = rank
    return highest_level


def _primary_event(events):
    """Return the event best suited to the panel report link.

    The most severe event wins, then the most recent one. Events without a
    URL are ignored.
    """
    candidates = [event for event in events if event.get('url')]
    if not candidates:
        return None

    def _sort_key(event):
        rank = _THREAT_LEVEL_RANK.get(event.get('threat_level'), -1)
        return rank, event.get('date') or ''

    return max(candidates, key=_sort_key)


def _summary(event_count, queried_instance_count, matched_instance_count, threat_level):
    """Build the one-line summary shown by the enrichment panel."""
    if not event_count:
        if not queried_instance_count:
            return 'No matching MISP events found.'
        instances = _plural(queried_instance_count, 'configured MISP instance', 'configured MISP instances')
        return f'No matching MISP events found in {queried_instance_count} {instances}.'

    events = _plural(event_count, 'matching MISP event', 'matching MISP events')
    summary = f'Found {event_count} {events}'
    if matched_instance_count:
        instances = _plural(matched_instance_count, 'MISP instance', 'MISP instances')
        summary += f' in {matched_instance_count} {instances}'
    if threat_level:
        summary += f'; highest threat level: {threat_level}'
    return f'{summary}.'


def misp_build_enrichment(report):
    """Build the native enrichment contribution for a MISP search report.

    :param report: list of MISP client results, one entry per instance.
    :return: dict suitable for merging into ``ioc.ioc_enrichment``, with the
        ``misp`` source key.
    """
    events, instances = _collect_events(report)
    threat_level = _highest_threat_level(events)
    primary_event = _primary_event(events)
    matched_instance_count = sum(1 for instance in instances if instance.get('event_count'))

    payload = {
        'summary': _summary(len(events), len(instances), matched_instance_count, threat_level),
        'match_status': 'matched' if events else 'no-match',
        'event_count': len(events),
    }

    if threat_level:
        payload['threat_level'] = threat_level

    tags = _bounded([tag for event in events for tag in event.get('tags') or []], _MAX_TAGS)
    if tags:
        payload['tags'] = tags

    classifications = _bounded(
        [classification for event in events for classification in event.get('classifications') or []],
        _MAX_CLASSIFICATIONS)
    if classifications:
        payload['classifications'] = classifications

    event_ids = _bounded([event.get('id') for event in events if event.get('id') is not None], _MAX_EVENT_IDS)
    if event_ids:
        payload['event_ids'] = event_ids

    organisations = _bounded(
        [event.get('organisation') for event in events if event.get('organisation')],
        _MAX_ORGANISATIONS)
    if organisations:
        payload['organisations'] = organisations

    if primary_event:
        payload['link'] = primary_event.get('url')

    if instances:
        payload['instances'] = instances
    if events:
        payload['events'] = events[:_MAX_EVENTS]
        if len(events) > _MAX_EVENTS:
            payload['events_truncated'] = True

    return {SOURCE_KEY: payload}


def misp_merge_reports(reports):
    """Merge several MISP client reports about the same IOC into one.

    A ``domain|ip`` IOC is searched by domain and by IP: both reports contain
    the matching events of the same MISP instances, and the native enrichment
    must show all of them instead of the result of the last search only.

    :param reports: iterable of MISP client reports.
    :return: list of instances, one entry per instance, with the events of
        every input report.
    """
    merged = []
    instances = {}
    for report in reports:
        if not isinstance(report, list):
            continue
        for entry in report:
            if not isinstance(entry, dict):
                continue
            instance_name = _string(entry.get('name'))
            instance_url = _string(entry.get('url'))
            results = entry.get('result')
            if not isinstance(results, list):
                results = []
            key = (instance_name, instance_url)
            if key not in instances:
                merged_entry = {
                    'name': instance_name,
                    'url': instance_url,
                    'result': [],
                }
                instances[key] = {
                    'entry': merged_entry,
                    'event_ids': set(),
                }
                merged.append(merged_entry)

            instance = instances[key]
            for result in results:
                event_id = _event_id(result) if isinstance(result, dict) else None
                if event_id is not None:
                    if event_id in instance['event_ids']:
                        continue
                    instance['event_ids'].add(event_id)
                instance['entry']['result'].append(result)
    return merged


def misp_merge_enrichment(existing_enrichment, contribution):
    """Merge a MISP enrichment contribution into existing enrichment data.

    Enrichment written by other modules is kept: their source keys are copied
    over untouched and only the ``misp`` key is replaced. A value that is not
    a dictionary (including None) is treated as empty enrichment data.

    :param existing_enrichment: current value of ``ioc.ioc_enrichment``.
    :param contribution: payload returned by :func:`misp_build_enrichment`.
    :return: the new ``ioc.ioc_enrichment`` value.
    """
    if isinstance(existing_enrichment, dict):
        merged = dict(existing_enrichment)
    else:
        merged = {}
    merged.update(contribution)
    return merged
