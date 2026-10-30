"""Offline review of Terraform JSON plans. Never calls AWS or applies changes."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

ACTIONS = {('no-op',), ('create',), ('read',), ('update',), ('delete',),
           ('delete', 'create'), ('create', 'delete'), ('forget',), ('create', 'forget')}
FIELDS = {
    'aws_ebs_volume': ('encrypted',),
    'aws_db_instance': ('storage_encrypted', 'deletion_protection'),
    'aws_vpc_security_group_ingress_rule': ('cidr_ipv4', 'cidr_ipv6', 'ip_protocol', 'from_port', 'to_port'),
}


def unknown(value):
    if isinstance(value, dict):
        return any(unknown(v) for v in value.values())
    if isinstance(value, list):
        return any(unknown(v) for v in value)
    return value is True


def review(plan):
    if not isinstance(plan, dict) or not re.fullmatch(r'1\.\d+', str(plan.get('format_version', ''))):
        raise ValueError('Expected Terraform plan JSON format 1.x')
    if not isinstance(plan.get('terraform_version'), str) or not isinstance(plan.get('planned_values'), dict):
        raise ValueError('Expected a saved plan, not state JSON or an arbitrary object')
    if not isinstance(plan.get('resource_changes', []), list):
        raise ValueError('resource_changes must be a list')
    findings, coverage, seen = [], [], set()

    def add(address, rule, message):
        findings.append({'address': address, 'rule': rule, 'message': message})

    for flag in ('errored', 'complete'):
        if flag in plan and not isinstance(plan[flag], bool):
            raise ValueError('Invalid plan completeness flag')
    incomplete = plan.get('errored', False) or plan.get('complete') is False or bool(plan.get('deferred_changes'))
    if incomplete:
        add('(plan)', 'PLAN_INCOMPLETE', 'Planning errored, deferred changes exist, or the plan is incomplete.')
    for item in plan.get('resource_changes', []):
        if not isinstance(item, dict):
            raise ValueError('Each resource change must be an object')
        address, kind, mode = item.get('address'), item.get('type'), item.get('mode')
        if not all(isinstance(v, str) and v for v in (address, kind, mode)) or mode not in ('managed', 'data'):
            raise ValueError('Resource address, type and valid mode are required')
        key = (address, item.get('deposed'))
        if not isinstance(key[1], (str, type(None))) or key in seen:
            raise ValueError('Duplicate or invalid resource identity')
        seen.add(key)
        change = item.get('change')
        if not isinstance(change, dict) or not isinstance(change.get('actions'), list):
            raise ValueError('Resource change/actions are required')
        actions = change['actions']
        if not all(isinstance(a, str) for a in actions) or tuple(actions) not in ACTIONS:
            raise ValueError('Unsupported Terraform action sequence')
        if mode == 'data' or actions in (['no-op'], ['read']):
            continue
        if 'delete' in actions:
            add(address, 'REPLACEMENT' if 'create' in actions else 'DELETE',
                'Resource replacement requires downtime/data review.' if 'create' in actions else 'Resource deletion requires ownership and recovery review.')
        if 'forget' in actions:
            add(address, 'FORGET', 'Terraform will stop managing an object; review ownership and orphan costs.')
        entry = {'address': address, 'type': kind, 'actions': actions,
                 'attribute_check': 'not applicable' if actions in (['delete'], ['forget']) else 'not covered'}
        coverage.append(entry)
        if actions in (['delete'], ['forget']):
            continue
        after = change.get('after')
        pending = change.get('after_unknown', {})
        if not isinstance(after, dict) or not isinstance(pending, dict):
            raise ValueError('Changed resource must contain after/after_unknown objects')
        if kind not in FIELDS:
            add(address, 'UNASSESSED_TYPE', 'Only lifecycle actions assessed; resource attributes need manual review.')
            continue
        fields = FIELDS[kind]
        if any(unknown(pending.get(f)) for f in fields):
            entry['attribute_check'] = 'unknown'
            add(address, 'UNKNOWN_ATTRIBUTE', 'A security-relevant value is unknown until apply; review cannot pass automatically.')
            continue
        entry['attribute_check'] = 'checked'
        if kind in ('aws_ebs_volume', 'aws_db_instance'):
            for field in fields:
                value = after.get(field)
                if not isinstance(value, bool):
                    add(address, 'MISSING_ATTRIBUTE', 'A required boolean security attribute is absent or invalid: ' + field)
                elif not value:
                    add(address, 'ENCRYPTION_DISABLED' if 'encrypt' in field else 'DELETION_PROTECTION_DISABLED',
                        'Planned security setting is disabled: ' + field)
        else:
            public = False
            cidrs = [after.get(f) for f in ('cidr_ipv4', 'cidr_ipv6') if after.get(f) is not None]
            for cidr in cidrs:
                if not isinstance(cidr, str):
                    raise ValueError('CIDR must be text')
                try:
                    public |= ipaddress.ip_network(cidr, strict=False).prefixlen == 0
                except (ValueError, TypeError):
                    raise ValueError('Invalid security-group CIDR') from None
            if not cidrs:
                # SG references and prefix lists need different reachability analysis.
                add(address, 'NON_CIDR_SOURCE', 'No known CIDR source; referenced groups/prefix lists require manual review.')
            protocol = str(after.get('ip_protocol', '')).lower()
            if protocol == '-1' and public:
                add(address, 'PUBLIC_ADMIN', 'World ingress includes all protocols and administrative ports.')
            elif protocol in ('tcp', '6'):
                low, high = after.get('from_port'), after.get('to_port')
                if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 65535:
                    raise ValueError('TCP ingress requires a valid port range')
                if public and any(low <= p <= high for p in (22, 3389)):
                    add(address, 'PUBLIC_ADMIN', 'World TCP ingress includes SSH or RDP; review access and network reachability.')
            elif protocol not in ('-1', 'udp', '17', 'icmp', '1', 'icmpv6', '58'):
                add(address, 'UNASSESSED_PROTOCOL', 'Ingress protocol is outside the supported protocol checks.')
    return {'schema': 1, 'scope': 'Changed managed resources only; selected AWS attributes and lifecycle actions.',
            'result': 'INCOMPLETE' if incomplete else 'REVIEW_REQUIRED' if findings else 'NO_FINDINGS_IN_SCOPE',
            'exit_code': 2 if incomplete else 1 if findings else 0,
            'findings': findings, 'coverage': coverage}


def markdown(report):
    # Encode user-controlled resource addresses as JSON strings in a fenced block;
    # escape backticks so addresses cannot close the block or inject Markdown.
    lines = ['# Terraform change review', '', 'Result: ' + report['result'], '',
             report['scope'], '', 'Input SHA256: ' + report['input_sha256'], '',
             'No resource values, policy documents or outputs are copied into this report.', '', '## Findings', '']
    for finding in report['findings']:
        address = json.dumps(finding['address']).replace('`', '\\u0060')
        lines += ['- ' + finding['rule'] + ': ' + finding['message'], '```text', address, '```', '']
    if not report['findings']:
        lines += ['No findings under these rules. This is not an approval to apply.', '']
    lines += ['## Coverage', '', '```json', json.dumps(report['coverage'], indent=2).replace('`', '\\u0060'), '```']
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    parser.add_argument('--output', type=Path, default=Path('reports/review'))
    args = parser.parse_args(argv)
    try:
        with args.plan.open('rb') as stream:
            raw = stream.read(50 * 1024 * 1024 + 1)
        if len(raw) > 50 * 1024 * 1024:
            raise ValueError('Plan exceeds the 50 MiB input limit')
        report = review(json.loads(raw))
        report['input_sha256'] = hashlib.sha256(raw).hexdigest()
        args.output.mkdir(parents=True, exist_ok=True)
        for name, content in [('report.json', json.dumps(report, indent=2) + '\n'), ('report.md', markdown(report))]:
            dest = args.output / name
            dest.touch(mode=0o600, exist_ok=True)
            dest.chmod(0o600)
            dest.write_text(content)
        print(report['result'] + ': ' + str(len(report['findings'])) + ' findings; ' + str(args.output))
        return report['exit_code']
    except (ValueError, OSError, TypeError) as exc:
        # Do not echo input values or parser excerpts, which may contain secrets.
        print('Review failed: invalid/unreadable plan or output path (' + type(exc).__name__ + ').', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
