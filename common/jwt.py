"""
+-----------------+------------------------------------------------------------------------+
| **Version**     | 0.1                                                                    |
+-----------------+------------------------------------------------------------------------+
| **Start**       | 27 Nov 2018                                                            |
+-----------------+------------------------------------------------------------------------+
| **Platform**    | Unix                                                                   |
+-----------------+------------------------------------------------------------------------+
| **Authors**     | Lucas Antognoni                                                        |
+-----------------+------------------------------------------------------------------------+
| **Description** | Security Tests for JWT authentication                                  |
+-----------------+------------------------------------------------------------------------+
| **Modifications**                                                                        |
+-----------------+-----------+------------------------------------------------------------+
| **Date**        | **Author**      | **Modification**                                     |
+-----------------+-----------+------------------------------------------------------------+
| 27 Nov 2018     | Lucas Antognoni | Base application structure                           |
+-----------------+-----------+------------------------------------------------------------+
| 27 Nov 2018     | Lucas Antognoni | Organizing application structure                     |
+-----------------+-----------+------------------------------------------------------------+
| 27 Nov 2018     | Lucas Antognoni | JWT tools                                            |
+-----------------+-----------+------------------------------------------------------------+

Implementation
==============
"""

import jwt
import hashlib
import datetime
import random
import string


# Create token with specified payload, private key and algorithm
def create_token(payload, private_key, algorithm):

    token = jwt.encode(payload, private_key, algorithm)

    return token


def custom_header(algorithm, type):

    header = {
        "alg": algorithm,
        "typ": type
    }

    return header


def custom_payload(claims, expiration=datetime.timedelta(hours=0)):

    payload = {}

    for c in claims:

        if c == 'identity':
            payload[c] = 'test_user'

        elif c == 'org_id':
            payload[c] = 'test_org'

        elif c == 'access':
            payload['type'] = 'access'

        elif c == 'refresh':
            payload['type'] = 'refresh'

        elif c == 'custom_access':
            payload['type'] = 'custom_type'

        elif c == 'fresh':
            payload[c] = True

        elif c == 'not_fresh':
            payload['fresh'] = False

        elif c == 'iss':
            payload[c] = hashlib.md5('issuer').hexdigest()

        elif c == 'exp':
            payload[c] = datetime.datetime.utcnow() + expiration

        elif c == 'iat':
            payload[c] = datetime.datetime.utcnow()

        elif c == 'nbf':
            payload[c] = datetime.datetime.utcnow()

        elif c == 'jti':
            jid = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
            payload[c] = hashlib.md5(jid).hexdigest()

        else:
            payload[c] = 'custom_claim'




