#Flask-HmacAuth
[![Build Status](https://travis-ci.org/Phillipmartin/flask-hmacauth.svg?branch=master)](https://travis-ci.org/Phillipmartin/flask-hmacauth)
A module to simplify HMAC-style authentication for RESTful APIs in Flask, which also builds in a simple RBAC concept and anti-replay via a timestamp.  For GET requests, the path section and all parameters are hashed.  For POST requests, the request body is added as well.  By default, the module expects authentication via an X-Auth-Signature header and ACCOUNT_ID and TIMESTAMP parameters (holding the obvious values) to be present in the query string or request body.  TIMESTAMP can be in any format datetime.fromtimestamp() can parse.  ACCOUNT_ID will be used to lookup a given account's secret and roles via an AccountBroker.  If auth fails, the application throws a 403 back to the client.  All of that can be changed, however.

The concept of an AccountBroker is used to separate this module from any actual user/role management logic.  2 trivial AccountBroker implementations have been provided.

#Example
##Server

    from flask import Flask
    from flask.ext.hmacauth import hmac_auth, DictAccountBroker, HmacManager

    app = Flask(__name__)
    accountmgr = DictAccountBroker(
        accounts={
            "admin": {"secret": ";hi^897t7utf", "rights": ["create", "edit", "delete", "view"]},
            "editor": {"secret": "afstr5afewr", "rights": ["create", "edit", "view"]},
            "guest": {"secret": "ASDFjoiu%i", "rights": ["view"]}
        })
    hmacmgr = HmacManager(accountmgr, app)
    ...
    @app.route('/api/v1/create')
    @hmac_auth("create")
    def create_thing():
        ...

##Client

    import requests
    import time
    import hashlib

    path_and_query = "/api/v1/create?TIMESTAMP="+str(int(time.time()))+"&ACCOUNT_ID=admin&foo=bar"
    host = "https://example.com"
    sig=hmac.new(";hi^897t7utf", digestmod=hashlib.sha1, msg=path_and_query).hexdigest()
    req = requests.get(host+path_and_query, headers={'X-Auth-Signature': sig})

#AccountBroker
An AccountBroker is an object that intermediates between the HMAC authentication and your user/account store.  It does this by exposing the following methods:

   * get_secret(account_id) - returns a string secret given an account ID.  If the account does not exist, returns None
   * has_rights(account_id, rights) - returns True if account_id has all of the rights in the list rights, otherwise returns False.  Returns False if the account does not exist.
   * is_active(account_id) - returns True if account_id is active (for whatever definition you want to define for active), otherwise returns False.

Flask-Hmacauth ships with 2 trivial AccountBroker implementations, a Dict-based AccountBroker (DictAccountBroker) and a static AccountBroker (StaticAccountBroker).

##DictAccountBroker
Takes a dict of format:

    {
        "accountID": {
            secret: "blahblah",
            rights: ["right1", "right2", "right3", ...]
        }
        ...
    }

it also exposes the add_accounts and del_accounts methods to modify accounts on the fly.

##StaticAccountBroker
Essentially disables all of the user and role management, and sets a static key for use in HMAC.  NOTE, if you use this class you need to pass StaticAccountBroker.GET_ACCOUNT to HmacManager as the account_id parameter OR supply a dummy value for ACCOUNT_ID in the query string

##Write your own
A very common case for larger applications will be user management via a database.  In that case, your AuthenticationBroker class just needs to perform the requisite SQL queries to satisfy the the methods above and you're good to go.

#HmacManager
This is the meat of the module.  This object contains the is_authorized method, which actually does the HMAC verification and role checks.

In the simple case, you just need to pass this object's constructor the flask application object and an AccountBroker object.  In more complex cases, where you want to change defaults, you have the following options:

   * app - this is the Flask application container
   * account_broker - this is the ApplicationBroker object
   * account_id - this is a callable, which when fed a request object will return the request's account ID.  The default value for this is lambda x: x.values.get('ACCOUNT_ID')
   * signature - this is a callable, which when fed a request object will return the request's signature.  The default value for this is GET_SIGNATURE = lambda x: x.headers.get('X-Auth-Signature').
   * timestamp - this is a callable, which when fed a request object will return the request's timestamp.  The default value for this is lambda x: x.values.get('TIMESTAMP')
   * valid_time - number of seconds that a signed request is valid (based on the signed timestamp).  defaults to 5
   * digest - digest type, defaults to hashlib.sha1

