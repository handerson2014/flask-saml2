# -*- coding: utf-8 -*-
import base64
import logging
import os
import urllib
import uuid
import zlib

from flask import Flask
from flask import redirect
from flask import request
from flask import url_for
from flask.ext.login import LoginManager
from flask.ext.login import UserMixin
from flask.ext.login import current_user
from flask.ext.login import login_required
from flask.ext.login import login_user
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

# PER APPLICATION configuration settings.
# Each SAML service that you support will have different values here.
idp_settings = {
    u'example.okta.com': {
        u"metadata": {
            "local": [u'/var/www/flask-saml2/example.okta.com.metadata']
        }
    },
}
app = Flask(__name__)
app.secret_key = str(uuid.uuid4())  # Replace with your secret key
login_manager = LoginManager()
login_manager.setup_app(app)
logging.basicConfig(level=logging.DEBUG)
# Replace this with your own user store
user_store = {}


class User(UserMixin):
    def __init__(self, user_id):
        user = {}
        self.id = None
        self.first_name = None
        self.last_name = None
        try:
            user = user_store[user_id]
            self.id = unicode(user_id)
            self.first_name = user['first_name']
            self.last_name = user['last_name']
        except:
            pass


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route("/")
def main_page():
    return "Hello"


@app.route("/saml/sso/<idp_name>", methods=['POST'])
def idp_initiated(idp_name):
    logging.warning("ddddddddddddddddddd")
    logging.warning(idp_name)
    
    settings = idp_settings[idp_name]
    settings['service'] = {
        'sp': {
            'endpoints': {
                'assertion_consumer_service': [
                    (request.url, BINDING_HTTP_REDIRECT),
                    (request.url, BINDING_HTTP_POST)
                ],
            },
            # Don't verify that the incoming requests originate from us via
            # the built-in cache for authn request ids in pysaml2
            'allow_unsolicited': True,
            'authn_requests_signed': False,
            'logout_requests_signed': True,
            'want_assertions_signed': True,
            'want_response_signed': False,
        },
    }
    logging.warning(settings)
    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True

    cli = Saml2Client(config=spConfig)
    try:
        authn_response = cli.parse_authn_request_response(
            request.form['SAMLResponse'],
            entity.BINDING_HTTP_POST)
        authn_response.get_identity()
        user_info = authn_response.get_subject()
        username = user_info.text
        valid = True
    except Exception as e:
        logging.error(e)
        valid = False
        return str(e), 401

    # "JIT provisioning"
    if username not in user_store:
        user_store[username] = {
            'first_name': authn_response.ava['FirstName'][0],
            'last_name': authn_response.ava['LastName'][0],
            }
    user = User(username)
    login_user(user)
    # TODO: If it exists, redirect to request.form['RelayState']
    return redirect(url_for('user'))


@app.route("/user")
@login_required
def user():
    msg = u"Hello {user.first_name} {user.last_name}".format(user=current_user)
    return msg


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    if port == 5000:
        app.debug = True
    app.run(host='0.0.0.0', port=port)
