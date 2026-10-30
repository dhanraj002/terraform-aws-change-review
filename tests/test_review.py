import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from review import review, markdown


def plan(kind='aws_ebs_volume', actions=None, after=None, pending=None):
    return {'format_version': '1.2', 'terraform_version': '1.13.0', 'planned_values': {},
            'complete': True, 'errored': False, 'resource_changes': [
                {'address': 'module.app.' + kind + '.example', 'mode': 'managed', 'type': kind,
                 'change': {'actions': actions or ['create'], 'before': None,
                            'after': {'encrypted': True} if after is None else after,
                            'after_unknown': pending or {}}}]}


def rules(value):
    return {f['rule'] for f in review(value)['findings']}


class ReviewTests(unittest.TestCase):
    def test_encrypted_volume_has_no_findings(self):
        self.assertEqual(review(plan())['exit_code'], 0)

    def test_deletion_and_both_replacement_orders(self):
        self.assertIn('DELETE', rules(plan(actions=['delete'])))
        for actions in [['delete', 'create'], ['create', 'delete']]:
            self.assertIn('REPLACEMENT', rules(plan(actions=actions)))

    def test_forget_is_not_a_safe_noop(self):
        self.assertIn('FORGET', rules(plan(actions=['forget'])))

    def test_missing_and_false_encryption(self):
        self.assertIn('MISSING_ATTRIBUTE', rules(plan(after={})))
        self.assertIn('ENCRYPTION_DISABLED', rules(plan(after={'encrypted': False})))
        self.assertIn('MISSING_ATTRIBUTE', rules(plan(after={'encrypted': 'true'})))

    def test_unknown_overrides_apparent_safe_value(self):
        self.assertIn('UNKNOWN_ATTRIBUTE', rules(plan(pending={'encrypted': True})))

    def test_irrelevant_unknown_does_not_block(self):
        self.assertEqual(review(plan(pending={'id': True}))['exit_code'], 0)

    def test_database_protection(self):
        p = plan('aws_db_instance', after={'storage_encrypted': True, 'deletion_protection': False})
        self.assertEqual(rules(p), {'DELETION_PROTECTION_DISABLED'})

    def test_world_ipv4_ipv6_and_port_ranges(self):
        for field, cidr in [('cidr_ipv4', '0.0.0.0/0'), ('cidr_ipv6', '::/0')]:
            for protocol, low, high in [('tcp', 20, 30), ('6', 3300, 3400), ('-1', None, None)]:
                p = plan('aws_vpc_security_group_ingress_rule', after={field: cidr, 'ip_protocol': protocol, 'from_port': low, 'to_port': high})
                self.assertIn('PUBLIC_ADMIN', rules(p))

    def test_private_ssh_and_public_https_not_admin(self):
        for cidr, port in [('10.0.0.0/8', 22), ('0.0.0.0/0', 443)]:
            p = plan('aws_vpc_security_group_ingress_rule', after={'cidr_ipv4': cidr, 'ip_protocol': 'tcp', 'from_port': port, 'to_port': port})
            self.assertEqual(review(p)['exit_code'], 0)

    def test_prefix_list_requires_manual_review(self):
        p = plan('aws_vpc_security_group_ingress_rule', after={'prefix_list_id': 'pl-example', 'ip_protocol': '-1'})
        self.assertIn('NON_CIDR_SOURCE', rules(p))

    def test_invalid_cidr_and_tcp_range_fail(self):
        for values in [{'cidr_ipv4': 'bad', 'ip_protocol': '-1'}, {'cidr_ipv4': '0.0.0.0/0', 'ip_protocol': 'tcp', 'from_port': 100, 'to_port': 10}]:
            with self.assertRaises(ValueError):
                review(plan('aws_vpc_security_group_ingress_rule', after=values))

    def test_unknown_type_never_silently_passes(self):
        self.assertIn('UNASSESSED_TYPE', rules(plan('aws_iam_role')))
        self.assertIn('UNASSESSED_TYPE', rules(plan('aws_security_group')))

    def test_noop_and_data_are_out_of_scope(self):
        self.assertEqual(review(plan(actions=['no-op']))['coverage'], [])
        p = plan(); p['resource_changes'][0]['mode'] = 'data'
        self.assertEqual(review(p)['coverage'], [])

    def test_incomplete_plan_takes_precedence(self):
        for flag, value in [('errored', True), ('complete', False), ('deferred_changes', [{}])]:
            p = plan(after={'encrypted': False}); p[flag] = value
            self.assertEqual(review(p)['exit_code'], 2)

    def test_empty_valid_plan(self):
        p = plan(); del p['resource_changes']
        self.assertEqual(review(p)['result'], 'NO_FINDINGS_IN_SCOPE')

    def test_state_and_major_versions_rejected(self):
        for p in [{}, {'format_version': '1.0', 'terraform_version': '1.13.0', 'values': {}}, dict(plan(), format_version='2.0')]:
            with self.assertRaises(ValueError): review(p)

    def test_duplicate_identity_and_unknown_action_rejected(self):
        p = plan(); p['resource_changes'] *= 2
        with self.assertRaises(ValueError): review(p)
        with self.assertRaises(ValueError): review(plan(actions=['surprise']))

    def test_deposed_resource_allowed(self):
        p = plan(); old = copy.deepcopy(p['resource_changes'][0]); old['deposed'] = 'abcd'; old['change']['actions'] = ['delete']
        p['resource_changes'].append(old)
        self.assertIn('DELETE', rules(p))

    def test_attribute_secrets_not_copied_into_report(self):
        p = plan(after={'encrypted': False, 'password': 'SECRET_CANARY'}); p['output_changes'] = {'secret': 'SECRET_CANARY'}
        r = review(p); r['input_sha256'] = 'test'
        self.assertNotIn('SECRET_CANARY', json.dumps(r) + markdown(r))

    def test_markdown_cannot_close_fence(self):
        p = plan(after={'encrypted': False}); p['resource_changes'][0]['address'] = '```\n![tracking](https://example.invalid)'
        r = review(p); r['input_sha256'] = 'test'
        self.assertNotIn('```\n![tracking]', markdown(r))

    def test_cli_exit_codes_and_private_report(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'plan.json'; output = Path(temp) / 'reports'
            for document, expected in [(plan(), 0), (plan(after={'encrypted': False}), 1), ({}, 2)]:
                source.write_text(json.dumps(document))
                r = subprocess.run([sys.executable, str(root / 'review.py'), str(source), '--output', str(output)], capture_output=True)
                self.assertEqual(r.returncode, expected)
            self.assertEqual((output / 'report.json').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
