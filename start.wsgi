#!/usr/bin/python

from index import app as application

import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/flask-saml2")
logging.warning('esto es')

