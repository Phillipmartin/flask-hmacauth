from flask import Flask
import requests
from urllib import urlencode
import datetime
import json

import pytest
from flask.ext.testing import LiveServerTestCase

from flask_hmacauth import hmac_auth
from flask_hmacauth.dict_account_broker import DictAccountBroker

from flask_hmacauth.hmac_manager import HmacManager

import logging

logging.basicConfig()
LOGGER = logging.getLogger("flask_hmacauth_test")


class LiveTest(LiveServerTestCase):

    def create_app(self):
        app = Flask(__name__)
        app.config["TESTING"] = True
        app.config["LIVESERVER_PORT"] = 8943

        account_broker = DictAccountBroker(
            accounts={
                # well formed account
                "valid_username": {
                    "secret": "valid_usernamesecret",
                    "rights": ["role1", "role2"]
                },
                # no rights, but still well formed
                "valid_username_no_rights": {
                    "secret": "test2secret",
                    "rights": []
                },
                # empty secret, still well formed (but silly)
                "invalid_username_empty": {
                    "secret": "",
                    "rights": ["role1", "role2"]
                },
                # None secret
                "invalid_username_none_secret": {
                    "secret": None,
                    "rights": ["role1", "role2"]
                },
                # missing secret
                "invalid_username_missing_secret": {
                    "rights": ["role1", "role2"]
                },
                # missing rights
                "invalid_username_missing_rights": {
                    "secret": "foo"
                }
            })
        self.hmac_manager = HmacManager(account_broker, app)
        self.session = requests.Session()

        @app.route("/authenticated", methods=["GET", "POST", "PUT", "DELETE"])
        @app.route("/authenticated/<foo>", methods=["GET", "POST", "PUT", "DELETE"])
        @hmac_auth("role1")
        def authenticated_role1(foo="default"):
            return "test"

        @app.route("/authenticated_two", methods=["GET", "POST", "PUT", "DELETE"])
        @app.route("/authenticated_two/<foo>", methods=["GET", "POST", "PUT", "DELETE"])
        @hmac_auth("role1")
        def authenticated_two_role1(foo="default"):
            return "test"

        @app.route("/anonymous", methods=["GET", "POST", "PUT", "DELETE"])
        def anonymous():
            return "valid_username"

        return app

    def get_server_url_parts(self):
        splitted = self.get_server_url().split("://")
        scheme = splitted[0] + "://"
        host = splitted[1]
        return (scheme, host, scheme + host)

    def create_signed_request(
            self, hmac_manager, account_id, method, canonical_uri, body, content_type, get_params_dict=None):
        (scheme, host, scheme_and_host) = self.get_server_url_parts()

        canonical_query_string = ""
        if get_params_dict is not None:
            canonical_query_string = urlencode(get_params_dict)

        new_headers = hmac_manager.sign_flask_request(
            method,
            host,
            canonical_uri,
            canonical_query_string,
            body,
            account_id,
            content_type
        )
        req = requests.Request(
            method=method,
            url=scheme + host + canonical_uri,
            headers=new_headers,
            files=None,
            data=body,
            params=get_params_dict,
            auth=None,
            cookies=None,
        )
        return req

    def send_request(self, request):
        prepared = request.prepare()
        resp = self.session.send(prepared)
        LOGGER.debug(str(resp))
        return resp

    def parse_authorization_header(self, authorization_header, lowercase=True):
        """
        Parse the authorization header string, for testing purposes.
        :param authorization_header: authorization request header str
        :return: a tuple of dicts, the first represents the raw k/v pairs as a dict, and the second is a copy but with the keys lowercased
        """
        parsed_auth = json.loads(authorization_header)
        if lowercase:
            parsed_auth = dict((k.lower(), v) for k, v in parsed_auth.iteritems())
        return parsed_auth

    def encode_authorization_header(self, authorization_header_dict):
        return json.dumps(authorization_header_dict)

    def test_sig_auth_header_has_valid_structure(self):
        # "version", "apikey", "signedheaders", "signature", "timestamp"
        (scheme, host, scheme_and_host) = self.get_server_url_parts()
        new_headers = self.hmac_manager.sign_flask_request(
            method="GET",
            host=host,
            canonical_uri=scheme + host + "/authenticated",
            canonical_query_string="?foo=bar",
            payload="",
            account_id="valid_username",
            content_type=""
        )

        # parse json and lowercase all keys
        parsed_auth_lc = self.parse_authorization_header(new_headers["Authorization"])

        expected_keys_list = ["version", "apikey", "signedheaders", "signature", "timestamp"]
        for (key, val) in parsed_auth_lc.iteritems():
            self.assertTrue(key.lower() in expected_keys_list)

        self.assertEqual(parsed_auth_lc["version"].lower(), u"HMAC4-SHA256".lower())
        self.assertEqual(parsed_auth_lc["apikey"], "valid_username")

        # signed headers csv list must contain content-type and host (and it does by default)
        # other headers can be selected by the user to be signed
        signed_headers_list = parsed_auth_lc["signedheaders"]
        default_signed_headers_list = ["content-type", "host"]
        for signed_header in signed_headers_list:
            self.assertIn(signed_header, default_signed_headers_list)

        self.assertRegexpMatches(
            parsed_auth_lc["signature"].strip(),
            "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
            "Signature should be a non-zero-length base64 encoded hmac signature"
        )

        # timestamp should be well-formed and not older than five seconds in the past utc (hopefully much less)
        actual_timestamp = datetime.datetime.strptime(parsed_auth_lc["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
        now_timestamp = datetime.datetime.utcnow()
        time_delta = now_timestamp - actual_timestamp
        self.assertLessEqual(time_delta.seconds, 5)

    def test_server_up_and_403_without_auth(self):
        response = requests.get(self.get_server_url() + "/authenticated")
        self.assertEqual(response.status_code, 403)

    def test_anonymous_routes_are_accessible(self):
        response = requests.get(self.get_server_url() + "/anonymous")
        self.assertEqual(response.status_code, 200)

    def test_get_with_valid_auth(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "GET",
            "/authenticated",
            "",
            "application/json",
            {"foo": "bar"}
        )
        resp = self.send_request(req)
        self.assertEqual(resp.status_code, 200)

    def test_post_with_valid_auth(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "POST",
            "/authenticated",
            "{\"foo\": \"bar\"}",
            "application/json"
        )
        resp = self.send_request(req)
        self.assertEqual(resp.status_code, 200)

    def test_put_with_valid_auth(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "PUT",
            "/authenticated",
            "{\"foo\": \"bar\"}",
            "application/json",
            get_params_dict={"foo": "unused"}
        )
        resp = self.send_request(req)
        self.assertEqual(resp.status_code, 200)

    def test_fail_authentication_when_method_tampered(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "GET",
            "/authenticated",
            "",
            "",
        )
        req.method = "POST"
        resp = self.send_request(req)
        self.assertEqual(resp.status_code, 403)

    def test_fail_authentication_when_content_type_header_tampered(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "POST",
            "/authenticated",
            body="{\"foo\": \"bar\"}",
            content_type="application/json",
        )
        LOGGER.debug("req.headers before: %s" % req.headers)
        req.headers["Content-Type"] = "application/xml"
        LOGGER.debug("req.headers after: %s" % req.headers)

        resp = self.send_request(req)
        self.assertEqual(resp.status_code, 403)

    def test_fail_authentication_when_host_header_tampered(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "POST",
            "/authenticated",
            body="{\"foo\": \"bar\"}",
            content_type="application/json",
        )
        LOGGER.debug("req.headers before: %s" % req.headers)
        req.headers["Host"] = "example.com"
        LOGGER.debug("req.headers after: %s" % req.headers)

        resp = self.send_request(req)
        self.assertEqual(resp.status_code, 403)

    def test_fail_authentication_when_query_string_tampered(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "GET",
            "/authenticated",
            "",
            "",
            get_params_dict={"foo": "bar"}
        )
        req.params = {"foo": "tampered_value"}
        resp = self.send_request(req)
        LOGGER.debug(str(resp))
        self.assertEqual(resp.status_code, 403)

    def test_fail_authentication_when_url_tampered(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "GET",
            "/authenticated",
            "",
            "",
            get_params_dict={"foo": "bar"}
        )

        req.url = self.get_server_url() + "/authenticated_two"
        resp = self.send_request(req)
        LOGGER.debug(str(resp))
        self.assertEqual(resp.status_code, 403)

    def test_fail_authentication_when_payload_tampered(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "POST",
            "/authenticated",
            "{\"foo\":\"bar\"}",
            "application/json",
            get_params_dict={"foo": "bar"}
        )
        req.data = "{\"foo\":\"tampered\"}"
        resp = self.send_request(req)
        LOGGER.debug(str(resp))
        self.assertEqual(resp.status_code, 403)

    def test_fail_authentication_when_authorization_header_apikey_tampered(self):
        req = self.create_signed_request(
            self.hmac_manager,
            "valid_username",
            "POST",
            "/authenticated",
            "{\"foo\":\"bar\"}",
            "application/json",
            get_params_dict={"foo": "bar"}
        )
        # tamper the authorization header, replace the real account id with a phony one
        auth_hdr_orig = req.headers["Authorization"]
        parsed = self.parse_authorization_header(req.headers["Authorization"])
        parsed["apikey"] = "mickey_mouse"
        req.headers["Authorization"] = self.encode_authorization_header(parsed)

        resp = self.send_request(req)
        LOGGER.debug(str(resp))
        self.assertEqual(resp.status_code, 403)


if __name__ == '__main__':
    pytest.main()
