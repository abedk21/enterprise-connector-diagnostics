import copy
import json
from pathlib import Path
import unittest
from connector_diagnostics import diagnose, sanitized

ROOT = Path(__file__).resolve().parent
CASES = json.loads((ROOT / 'scenarios.json').read_text(encoding='utf-8'))


class ConnectorDiagnosticsTests(unittest.TestCase):
    def codes(self, key):
        return {x['code'] for x in diagnose(CASES[key])['findings']}

    def test_missing_scopes_and_permissions(self):
        self.assertEqual(self.codes('missing_scope'), {'MISSING_SCOPES','HTTP_403'})

    def test_expiry_and_unauthorized(self):
        self.assertEqual(self.codes('expired'), {'TOKEN_EXPIRED','HTTP_401'})

    def test_rate_limit_and_retry_after(self):
        result=diagnose(CASES['rate_limited'])
        self.assertEqual({x['code'] for x in result['findings']},{'HTTP_429'})
        self.assertIn('15s', result['findings'][0]['observed'])

    def test_wrong_audience(self):
        self.assertIn('AUDIENCE_MISMATCH', self.codes('wrong_audience'))

    def test_healthy(self):
        self.assertEqual(diagnose(CASES['healthy'])['result'], 'checks_passed')

    def test_redacts_nested_credentials(self):
        value={'access_token':'raw-token','nested':[{'client_secret':'private','user':'example'}]}
        out=sanitized(value)
        self.assertEqual(out['access_token'],'[REDACTED]')
        self.assertEqual(out['nested'][0]['client_secret'],'[REDACTED]')
        self.assertEqual(out['nested'][0]['user'],'example')

    def test_diagnostic_output_does_not_expose_tokens(self):
        case=copy.deepcopy(CASES['healthy'])
        case['identity']['access_token']='SENSITIVE-PLACEHOLDER'
        self.assertNotIn('SENSITIVE-PLACEHOLDER',json.dumps(diagnose(case)))

    def test_multiple_faults_reported_without_short_circuit(self):
        case=copy.deepcopy(CASES['missing_scope'])
        case['identity']['audience']='wrong'
        case['identity']['expires_at']=10
        codes={f['code'] for f in diagnose(case)['findings']}
        self.assertEqual(codes,{'AUDIENCE_MISMATCH','TOKEN_EXPIRED','MISSING_SCOPES','HTTP_403'})

    def test_retry_after_is_bounded(self):
        case=copy.deepcopy(CASES['rate_limited'])
        case['response']['retry_after_seconds']=1000
        result=diagnose(case)
        self.assertIn('120s',result['findings'][0]['observed'])


if __name__ == '__main__':
    unittest.main()
