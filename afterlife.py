#!/usr/bin/env python3
"""Offline, evidence-aware IOC triage. Python standard library only."""
import argparse
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('timestamp must be a string')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timestamps must include a timezone')
    return parsed.astimezone(timezone.utc)


def indicator(kind, value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('value must be a nonempty string')
    value = value.strip()
    if kind == 'ip':
        return str(ipaddress.ip_address(value))
    if kind == 'domain':
        value = value.rstrip('.').encode('idna').decode('ascii').lower()
        if len(value) > 253 or any(not p or len(p) > 63 or p[0] == '-' or p[-1] == '-' or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in p) for p in value.split('.')):
            raise ValueError('invalid domain')
        return value
    if kind == 'sha256':
        if len(value) != 64 or any(c not in '0123456789abcdefABCDEF' for c in value):
            raise ValueError('invalid SHA256')
        return value.lower()
    raise ValueError('type must be ip, domain, or sha256')


def analyze(rows, now, ttl):
    groups = {}
    for number, row in rows:
        try:
            if not isinstance(row, dict):
                raise ValueError('record must be an object')
            kind = row['type']
            value = indicator(kind, row['value'])
            source = row['source']
            if not isinstance(source, str) or not source.strip():
                raise ValueError('source must be a nonempty string')
            verdict = row['verdict']
            if verdict not in ('malicious', 'benign', 'revoked'):
                raise ValueError('invalid verdict')
            seen = timestamp(row['observed_at'])
            if seen > now:
                raise ValueError('observed_at is in the future')
            expires = timestamp(row['valid_until']) if 'valid_until' in row else None
            if expires and expires < seen:
                raise ValueError('valid_until precedes observed_at')
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise ValueError(f'line {number}: {exc}') from exc
        key = (kind, value)
        # A source supersedes only its own older assessment. Preserve tied conflicts.
        evidence = dict(source=source.strip(), verdict=verdict, observed_at=seen, expires=expires)
        groups.setdefault(key, []).append(evidence)
    result = []
    for (kind, value), records in sorted(groups.items()):
        latest = {}
        for r in records:
            latest[r['source']] = max(latest.get(r['source'], r['observed_at']), r['observed_at'])
        evidence, active = [], set()
        for r in records:
            age = (now - r['observed_at']).total_seconds() / 86400
            superseded = r['observed_at'] < latest[r['source']]
            stale = now >= r['expires'] if r['expires'] else age >= ttl
            if not stale and not superseded:
                active.add(r['verdict'])
            evidence.append(dict(source=r['source'], verdict=r['verdict'], age_days=round(age, 2), stale=stale, superseded=superseded))
        if len(active) > 1:
            status = 'CONFLICT_REVIEW'
        elif active == {'malicious'}:
            status = 'ACTIVE_REVIEW'
        elif active == {'benign'}:
            status = 'BENIGN_REVIEW'
        elif active == {'revoked'}:
            status = 'REVOKED_REVIEW'
        else:
            status = 'STALE_REVIEW'
        result.append(dict(type=kind, value=value, status=status, evidence=evidence))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input', type=Path, help='JSONL evidence file')
    p.add_argument('--now', help='ISO8601 timezone-aware evaluation time')
    p.add_argument('--ttl-days', type=int, default=30, help='fallback lifetime; default 30')
    p.add_argument('--json', action='store_true', help='emit machine-readable report')
    args = p.parse_args()
    try:
        if args.ttl_days <= 0:
            raise ValueError('ttl-days must be positive')
        now = timestamp(args.now) if args.now else datetime.now(timezone.utc)
        rows = []
        with args.input.open(encoding='utf-8') as stream:
            for n, line in enumerate(stream, 1):
                if line.strip():
                    try:
                        rows.append((n, json.loads(line)))
                    except json.JSONDecodeError as exc:
                        raise ValueError(f'line {n}: invalid JSON') from exc
        report = analyze(rows, now, args.ttl_days)
    except (OSError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(dict(evaluated_at=now.isoformat(), indicators=report), indent=2))
    else:
        for item in report:
            print(f"{item['status']:17} {item['type']:6} {item['value']}")
        print(f'{len(report)} indicators reviewed. No blocklists modified.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
