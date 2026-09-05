import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from app.workflow import analyze, normalize
from app import server

class WorkflowTests(unittest.TestCase):
    def test_no_network(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS prohibited')), patch('socket.create_connection', side_effect=AssertionError('Network prohibited')):
            self.assertEqual(analyze('https://example.com')['risk'], 'low')
            self.assertEqual(analyze('http://paypal-account-verify.example.com/login?redirect=secret')['risk'], 'high')

    def test_private_and_ambiguous_targets(self):
        for url in ['http://127.0.0.1','http://10.0.0.1','http://192.168.1.1','http://169.254.169.254','http://172.16.0.1','http://[::1]','http://[::ffff:127.0.0.1]','http://[fc00::1]','http://localhost','http://a.local','http://foo.internal','http://foo.home.arpa','http://2130706433','http://0177.0.0.1','http://0x7f000001','http://0x7f.0.0.1','file:///etc/passwd','javascript:alert(1)','http://example.com\\@127.0.0.1','https://user:secret@example.com','http://example.com:bad','http://example.com\n.evil.com','http://224.0.0.1']:
            with self.subTest(url=url), self.assertRaises(ValueError):normalize(url)

    def test_selected_tools_and_redaction(self):
        r=analyze('https://xn--pple-43d.example.com/login?next=SECRET#TOKEN')
        self.assertIn('query_inspection',r['tools'])
        self.assertIn('internationalized_hostname',r['tools'])
        self.assertNotIn('SECRET',json.dumps(r))
        self.assertNotIn('TOKEN',json.dumps(r))
        self.assertNotIn('query_inspection',analyze('example.com')['tools'])

    def test_review_gate_and_sum(self):
        low=analyze('https://example.com/about'); high=analyze('http://paypal-account-verify.example.com/login')
        self.assertFalse(low['review_required']); self.assertTrue(high['review_required'])
        self.assertEqual(high['score'],min(100,sum(e['weight'] for e in high['evidence'])))
        self.assertEqual(high['stages'][-1]['status'],'waiting')
        self.assertEqual(analyze('https://paypal.com/login')['risk'],'low')
        self.assertTrue(any(e['id']=='host.brand.paypal' for e in analyze('https://paypal.com.evil.example/login')['evidence']))

class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(); server.DB=Path(cls.tmp.name)/'test.sqlite3'
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True);cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.http.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();cls.thread.join();cls.tmp.cleanup()
    def req(self,path,data=None,headers=None):
        req=Request(self.base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers or {'Content-Type':'application/json'})
        try:
            with urlopen(req) as r:return r.status,json.loads(r.read())
        except HTTPError as e:return e.code,json.loads(e.read())
    def test_full_workflow_persistence_review_and_conflict(self):
        status,case=self.req('/api/analyze',{'url':'http://paypal-verify.example.com/login?next=SECRET'})
        self.assertEqual(status,201)
        path='/api/cases/'+case['id']
        self.assertEqual(self.req(path)[1]['id'],case['id'])
        self.assertEqual(self.req(path+'/review',{'decision':'suspicious','note':'Unexpected sender; verify out of band.'})[1]['status'],'reviewed')
        self.assertEqual(self.req(path+'/review',{'decision':'likely_legitimate','note':'overwrite'})[0],409)
        saved=self.req(path)[1]
        self.assertEqual(saved['review']['decision'],'suspicious')
        self.assertNotIn('SECRET',json.dumps(saved))
        self.assertTrue(any(c['id']==case['id'] for c in self.req('/api/cases')[1]['cases']))
    def test_invalid_requests_and_origin(self):
        self.assertEqual(self.req('/api/analyze',{'url':'http://127.0.0.1'})[0],400)
        self.assertEqual(self.req('/api/analyze',[])[0],400)
        self.assertEqual(self.req('/api/analyze',{'url':'example.com'}, {'Content-Type':'application/json','Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.req('/api/analyze',{'url':'a'*9000})[0],413)
        self.assertEqual(self.req('/api/analyze',{'url':'example.com'},{'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.req('/api/cases/missing')[0],404)
        self.assertEqual(self.req('/../README.md')[0],404)
    def test_escalation_and_validation(self):
        _,case=self.req('/api/analyze',{'url':'example.com'})
        p='/api/cases/'+case['id']+'/review'
        self.assertEqual(self.req(p,{'decision':'suspicious','note':''})[0],400)
        self.assertEqual(self.req(p,{'decision':'approve','note':'unsupported'})[0],400)
        status,result=self.req(p,{'decision':'needs_investigation','note':'Need sender context.'})
        self.assertEqual(status,200);self.assertEqual(result['status'],'escalated')
    def test_health_and_security_headers(self):
        self.assertEqual(self.req('/api/health')[1]['mode'],'offline rules')
        with urlopen(self.base) as r:
            self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy'])
            self.assertEqual(r.headers['X-Content-Type-Options'],'nosniff')

if __name__=='__main__':unittest.main()
