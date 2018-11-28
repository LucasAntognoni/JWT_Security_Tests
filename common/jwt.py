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
+-----------------+------------------------------------------------------------------------+
| 27 Nov 2018     | Lucas Antognoni | Base application structure                           |
+-----------------+------------------------------------------------------------------------+
| 27 Nov 2018     | Lucas Antognoni | Organizing application structure                     |
+-----------------+------------------------------------------------------------------------+
| 27 Nov 2018     | Lucas Antognoni | JWT tools                                            |
+-----------------+------------------------------------------------------------------------+
| 27 Nov 2018     | Lucas Antognoni | Started tests development                            |
+-----------------+------------------------------------------------------------------------+
| 28 Nov 2018     | Lucas Antognoni | None & claims tests and started RSA to HMAC attack   |
+-----------------+------------------------------------------------------------------------+


Implementation
==============
"""

import jwt
import json
import datetime
import base64


def create_token(payload, key, algorithm):

    token = jwt.encode(payload, key, algorithm)

    return token


def custom_header(algorithm, type):
    header = {
        "alg": algorithm,
        "typ": type
    }

    str = json.dumps(header)
    enc = str.encode()

    return base64.urlsafe_b64encode(enc).replace(b'+', b'-').replace(b'/', b'_').replace(b'=', b'')


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
            payload[c] = '3f95329783d2f4d0711bba881f37b41b'

        elif c == 'exp':
            payload[c] = datetime.datetime.utcnow() + expiration

        elif c == 'iat':
            payload[c] = datetime.datetime.utcnow()

        elif c == 'nbf':
            payload[c] = datetime.datetime.utcnow()

        elif c == 'jti':
            payload[c] = 'c18993a47807863b69e1749f2db7d09e'

        else:
            payload[c] = 'custom_claim'

    return payload


def append_custom_header(token, header):
    split_token = token.split(b'.')

    forged_token = header + b'.' + split_token[1] + b'.' + split_token[2]

    return forged_token
