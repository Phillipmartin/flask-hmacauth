
from flask import Flask
from flask.ext.hmacauth import DictAccountBroker, HmacManager, hmac_auth, StaticAccountBroker
import pytest
from flask.ext.testing import TestCase
import time
import hashlib
import hmac


def mkdictapp():
    app = Flask(__name__)
    app.config['TESTING'] = True
    accountmgr = DictAccountBroker(
        accounts={
            #well formed account
            "test1": {"secret": "test1secret", "rights": ["role1", "role2"]},
            #no rights, but still well formed
            "test2": {"secret": "test2secret", "rights": []},
            #empty secret, still well formed (but silly)
            "test3": {"secret": "", "rights": ["role1", "role2"]},
            #None secret
            "test4": {"secret": None, "rights": ["role1", "role2"]},
            #missing secret
            "test5": {"rights": ["role1", "role2"]},
            #missing rights
            "test6": {"secret": "foo"}
        })
    hmacmgr = HmacManager(accountmgr, app)

    @app.route("/test")
    @hmac_auth(rights="role1")
    def test():
        return "test"

    @app.route("/test1")
    @hmac_auth(rights=["role1"])
    def test1():
        return "test1"

    @app.route("/test2")
    @hmac_auth(["role1", "role2"])
    def test2():
        return "test2"

    @app.route("/test3")
    @hmac_auth(["role1", "role2", "role3"])
    def test3():
        return "test3"

    @app.route("/test4")
    @hmac_auth()
    def test4():
        return "test4"

    @app.route("/test5")
    def test5():
        return "test5"

    return app

def mkstaticapp():
    app = Flask(__name__)
    app.config['TESTING'] = True
    accountmgr = StaticAccountBroker(secret="supersecret")
    hmacmgr = HmacManager(accountmgr, app, account_id=lambda x: "foo", valid_time=20)

    @app.route("/test")
    @hmac_auth()
    def test():
        return "test"

    @app.route("/test1")
    def test1():
        return "test1"

    return app

class StaticAuthTest(TestCase):
    def create_app(self):
        return mkstaticapp()

    def test_no_auth(self):
        url = "/test1"
        req = self.client.open(url)
        self.assert_200(req)
        self.assertEquals(req.data,  'test1')

    def test_auth(self):
        url = "/test?TIMESTAMP="+str(int(time.time()))+"&foo=bar"
        sig = hmac.new("supersecret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_200(req)
        self.assertEquals(req.data,  'test')

    def test_bad_auth(self):
        url = "/test?TIMESTAMP="+str(int(time.time()))+"&foo=bar"
        sig = hmac.new("notsupersecret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)


class DictAuthTest(TestCase):
    def create_app(self):
        return mkdictapp()

    #endpoint with no auth
    def test_no_auth(self):
        url = "/test5"
        req = self.client.open(url)
        self.assert_200(req)
        self.assertEquals(req.data,  'test5')

    #rights tests
    def test_rights_string(self):
        url = "/test?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test1&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_200(req)
        self.assertEquals(req.data,  'test')

    def test_rights_list(self):
        url = "/test1?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test1&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        #req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_200(req)
        self.assertEquals(req.data,  'test1')

    def test_multi_rights_list(self):
        url = "/test2?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test1&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_200(req)
        self.assertEquals(req.data,  'test2')

    def test_lacking_right(self):
        url = "/test3?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test1&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)

    def test_missing_rights_key(self):
        url = "/test4?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test2&foo=bar"
        sig = hmac.new("test2secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.get(url, headers={'X-Auth-Signature': sig})
        self.assertEquals(req.data,  'test4')

    def test_empty_acct_rights(self):
        url = "/test2?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test2&foo=bar"
        sig = hmac.new("test2secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)

    def test_no_acct_rights(self):
        url = "/test2?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test6&foo=bar"
        sig = hmac.new("foo", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)

    #Time tests
    def test_time_expired(self):
        url = "/test1?TIMESTAMP="+str(int(time.time())-30)+"&ACCOUNT_ID=test1&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)

    def test_time_in_future(self):
        url = "/test1?TIMESTAMP="+str(int(time.time())+60)+"&ACCOUNT_ID=test1&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)

    def test_missing_time(self):
        url = "/test1?ACCOUNT_ID=test1&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)

    #key tests
    def test_bad_account(self):
        url = "/test1?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test7&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)

    def test_missing_sig(self):
        url = "/test1?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test1&foo=bar"
        req = self.client.open(url)
        self.assert_403(req)

    def test_missing_account(self):
        url = "/test1?TIMESTAMP="+str(int(time.time()))+"&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)

    def test_bad_sig(self):
        url = "/test1?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=test1&foo=bar"
        sig = hmac.new("test1secret", msg=url, digestmod=hashlib.sha1).hexdigest()
        url += "&bar=baz"
        req = self.client.open(url, headers={'X-Auth-Signature': sig})
        self.assert_403(req)

    #TODO: tests for POSTs

if __name__ == '__main__':
    pytest.main()