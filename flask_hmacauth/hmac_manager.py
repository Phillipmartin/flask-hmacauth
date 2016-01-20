"""
    flask.ext.hmacauth
    ---------------

    This module provides HMAC-based authentication and authorization for
    Flask. It lets you work with requests in a database-independent manner.

initiate the HmacManager with a app and set account ID, signature and timestamp
"""

from flask import request
import hmac
import hashlib
import datetime
import logging
from base64 import b64encode
import json

from .exceptions import AuthorizationError, AuthenticationError
from .util import constant_time_compare, from_utc

logging.basicConfig()
LOGGER = logging.getLogger("flask_ext_aws_hmac_auth")
LOGGER.setLevel(logging.DEBUG)

class HmacManager(object):
    """
    This object is used to hold the settings for authenticating requests.  Instances of
    :class:`HmacManager` are not bound to specific apps, so you can create one in the
    main body of your code and then bind it to your app in a factory function.
    """

    # algorithm identity string, used to ensure compatibility
    algorithm_name = "HMAC4-SHA256"

    def __init__(self, account_broker, app=None, valid_time=300):
        """
        :param account_broker: AccountBroker object holding user account info :type AccountBroker
        :param app: Flask application container (default None)
        :param valid_time :type integer, number of seconds a timestamp remains valid (default 300 seconds)
        """
        self._account_broker = account_broker
        self._valid_time = valid_time

        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        Sets the hmac_manager attribute on the flask app object provided.
        :param app: flask app object
        :return: None
        """
        app.hmac_manager = self

    def is_authorized(self, request_obj, required_rights):
        """
        Called by the @hmac_auth decorator. Checks the authorization headers before allowing the request to proceed.
        If authentication fails for any reason, an AuthenticationError is thrown.
        If the user is not authorized based on the required_rights specified, an AuthorizationError is thrown.
        Any exceptions will be caught by the @hmac_auth decorator and used to abort the request.

        :param request_obj: flask request object
        :param required_rights: list of rights required to access the resource :type list
        :return: None
        """
        headers = request_obj.headers
        raw_authorization = None
        for header, value in headers.items():
            if header.lower() == "authorization":
                raw_authorization = value
        if raw_authorization is None:
            raise AuthenticationError("No authorization header found, auth failed")

        authorization = self._parse_authorization_header(raw_authorization)
        if authorization is None:
            raise AuthenticationError("Failed to parse authorization header")

        apikey = authorization["apikey"]
        version = authorization["version"]
        raw_timestamp = authorization["timestamp"]
        signed_headers = authorization["signedheaders"]
        client_signature = authorization["signature"]

        ts = from_utc(raw_timestamp)
        utc_zulu = ts.isoformat() + "Z"

        # is the timestamp valid?
        acceptable_skew = datetime.timedelta(seconds=self._valid_time)
        now = datetime.datetime.utcnow()

        ts_lower_bounds = now-acceptable_skew
        ts_upper_bounds = now+acceptable_skew
        if ts < ts_lower_bounds or ts > ts_upper_bounds:
            raise AuthenticationError("Timestamp %s out of range %s, %s" % (ts, ts_lower_bounds, ts_upper_bounds))

        if version.lower() != self.algorithm_name.lower():
            raise AuthenticationError("Algorithm name mismatch, may be different version? %s != %s" % (
            version.lower(), self.algorithm_name))

        # is the account active, valid, etc?
        if not self._account_broker.is_active(apikey):
            raise AuthenticationError("apikey invalid or inactive: %s" % apikey)

        payload = request.get_data(cache=True, as_text=False, parse_form_data=False)
        canonical_uri = request_obj.script_root + request_obj.path
        canonical_request, signed_headers = self._get_canonical_request(
            request_obj.method,
            request_obj.headers,
            canonical_uri,
            request_obj.query_string,
            payload,
            signed_headers)
        string_to_sign = self._get_string_to_sign(utc_zulu, apikey, canonical_request)

        # do we have a secret and rights for this account?
        # implicitly, does this account exist?
        secret = self._account_broker.get_secret(apikey)
        if secret is None:
            raise AuthenticationError("No secret configured for this apikey")

        server_signature = self._compute_signature(secret, string_to_sign)

        # constant time comparison, be wary of timing attacks
        if not constant_time_compare(client_signature, server_signature):
            raise AuthenticationError("Signature mismatch")

        # TODO(daslanian): maybe we should require that the user specifies at least one required_right?
        if required_rights is not None:
            if isinstance(required_rights, str):
                required_rights = [required_rights]

            if not self._account_broker.has_rights(apikey, required_rights):
                raise AuthorizationError
        return True

    def _get_canonical_headers(self, raw_headers, signed_headers):
        """
        This lists the headers in the canonical_headers list, trimmed/lowercased and delimited with ";" and in alpha order.
        Note: The request can include any headers; signed_headers include those that you want to be included in the hash of the request.
        "Host" and "Content-Type" are always required.

        :param raw_headers: request headers dictionary with dict keys lowercased :type dict
        :param signed_headers: lowercased list of request headers that should be signed :type list
        :return (signed_headers, canonical_headers, content_type,)
        """
        signed_headers = [header.strip().lower() for header in sorted(signed_headers)]
        canonical_headers = ""
        for signed_header in signed_headers:
            canonical_headers += signed_header + ":" + raw_headers[signed_header] + "\n"
        return signed_headers, canonical_headers, raw_headers["content-type"]

    def _get_canonical_request(self, method, headers, canonical_uri, canonical_querystring, payload, signed_headers):
        """
        Generates the canonical request (to be signed) given all of the data needed.
        Canonical request is in format:
        <method>\n
        <canonical_uri>\n
        <canonical_querystring>\n
        <canonical_headers>\n
        <signed_headers_csv>\n
        <payload>\n

        :param method: HTTP method :type str
        :param headers: list of raw headers from the request :type list
        :param canonical_uri: canonical :type str
        """
        headers = dict((k.lower(), v) for (k, v) in headers.items())
        signed_headers = [value.strip().lower() for value in signed_headers]

        # TODO remove content-type?
        signed_headers_list, canonical_headers, content_type = self._get_canonical_headers(headers, signed_headers)

        canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + ",".join(
            signed_headers_list) + '\n' + payload + "\n"
        return canonical_request, signed_headers_list

    def _compute_signature(self, signing_key, string_to_sign):
        """
        Compute the HMAC signature given the signing key and the string to sign.
        Returns the base64 encoded signature.

        :param signing_key: HMAC key :type str
        :param string_to_sign: plaintext that needs to be signed :type str
        :return: base64 encoded HMAC signature :type str
        """
        raw_sig =  hmac.new(
            signing_key,
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return b64encode(raw_sig)

    def _get_string_to_sign(self, utc_zulu, account_id, canonical_request):
        """
        Constructs the final string to sign, which is in format: <utc>\n<account_id>\n<canonical_request>.
        No trailing newline is used.

        :param utc_zulu: UTC time :type str
        :param account_id: ID of the account that will be used to sign the request :type str
        :param canonical_request: canonical request generated by _get_canonical_request() :type str
        :return: string to sign :type str
        """
        return "%s\n%s\n%s" % (utc_zulu, account_id, canonical_request)

    def _generate_authorization_header(self, account_id, signed_headers_csv, signature, timestamp):
        """
        Used by the HMAC signing (client) code to generate an authorization header from the reqd fields.
        :param account_id: account ID to use for signing :type str
        :param signed_headers_csv: csv separated list of headers that are being signed :type str
        :param signature: base64-encoded HMAC signature computed :type str
        :param timestamp: current UTC timestamp used during signing :type str
        :return:
        """
        return json.dumps(
            {
                "Version": self.algorithm_name,
                "APIKey": account_id,
                "Signature": signature,
                "SignedHeaders": signed_headers_csv,
                "Timestamp": timestamp,
            }
        )

    def _parse_authorization_header(self, authorization_hdr):
        """
        Used by the HMAC verification code to parse the authorization header present in the request.
        Parses authorization header string in the following format:
            Version:HMAC4-SHA256,APIKey:<account_id>,SignedHeaders:<csv_list_of_signed_header_keys>,Signature:<b64_encoded_sig>,Timestamp:<utc_timestamp_str>

        :param authorization_hdr: string taken from the Authorization: request header (value only) :type str
        :return: dictionary of parsed authorization fields (keys: version, apikey, signedheaders, signature, timestamp)
        """
        # parse authorization_hdr as json and return as a dict with lowercased keys
        parsed_auth = dict((k.lower(), v) for (k, v) in json.loads(authorization_hdr).items())

        for required_key in ["version", "apikey", "signedheaders", "signature", "timestamp"]:
            if required_key not in parsed_auth:
                raise AuthenticationError("Missing required key in authorization header: %s", required_key)
        parsed_auth["signedheaders"] = [header.strip().lower() for header in parsed_auth["signedheaders"]]
        return parsed_auth

    # TODO(daslanian): rename this function
    def sign_flask_request(self, method, host, canonical_uri, canonical_query_string, payload, account_id,
                           content_type):
        """
        API clients call this function, passing details about the request and the account_id it should be signed with.
        This function then signs the request and returns a dictionary of authentication headers that must be included
        with the request (Content-Type, Authorization).

        :param method: HTTP method string
        :param host: host and port, no scheme included (e.g., google.com:80)
        :param canonical_uri: url path (e.g. /api/v.1.foo)
        :param canonical_query_string: query string (e.g. foo=bar&baz=bash)
        :param payload: HTTP payload/body of request (must include payload if it exists, regardless of HTTP method)
        :param account_id: account holder of the signing creds
        :param content_type: HTTP content-type (e.g. application/json)
        """
        ts = datetime.datetime.utcnow()
        utc_zulu = ts.strftime('%Y-%m-%dT%H:%M:%SZ')

        # Combine elements to create create canonical request
        headers = {"Host": host, "Content-type": content_type}
        canonical_request, signed_headers_list = self._get_canonical_request(
            method,
            headers,
            canonical_uri,
            canonical_query_string,
            payload,
            signed_headers=['content-type', 'host'])

        string_to_sign = self._get_string_to_sign(utc_zulu, account_id, canonical_request)

        # create signing key and signature
        secret = self._account_broker.get_secret(account_id)
        if secret is None:
            raise ValueError("No secret configured for the account_id specified- did you pass an invalid account_id?")

        # generate the authorization header using the signature and other meta
        authorization_header = self._generate_authorization_header(
            account_id,
            signed_headers_list,
            self._compute_signature(secret, string_to_sign),
            utc_zulu)

        # note that the 'host' request header is added automatically by the Python 'requests' library.
        return {
            "Content-Type": content_type,
            "Authorization": authorization_header
        }
