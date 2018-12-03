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
| 29 Nov 2018     | Lucas Antognoni | Finished all tests and started code documentation    |
+-----------------+------------------------------------------------------------------------+
| 29 Nov 2018     | Lucas Antognoni | Upgrading tests robustness                           |
+-----------------+------------------------------------------------------------------------+
| 29 Nov 2018     | Lucas Antognoni | Started documentation with Sphinx                    |
+-----------------+------------------------------------------------------------------------+
| 03 Dec 2018     | Lucas Antognoni | Finished documentation                               |
+-----------------+------------------------------------------------------------------------+


Implementation
==============
"""

import json
import datetime
import base64

from . import pyjwt


def create_token(payload, key, algorithm):
    """
        Creates JWT token using custom pyjwt lib.

        Author:
            Lucas Antognoni

        Arguments:
            payload     (dict): The token payload.
            key         (str):  Key or secret for signing.
            algorithm   (str):  Signing algorithm.

        Response:
            token   (str):  JWT.
    """

    token = pyjwt.encode(payload, key, algorithm)

    return token


def custom_header(algorithm, media):
    """
        Creates JWT header.

        Author:
            Lucas Antognoni

        Arguments:
            algorithm   (str):  Signing algorithm.
            media        (str):  Media type of JWS.

        Response:
            header  (bytes):  Base64 encoded header.
    """

    header = {
        "alg": algorithm,
        "typ": media
    }

    str = json.dumps(header)
    enc = str.encode()

    return base64.urlsafe_b64encode(enc).replace(b'+', b'-').replace(b'/', b'_').replace(b'=', b'')


def custom_payload(claims, expiration):
    """
        Creates JWT payload.

        Author:
            Lucas Antognoni

        Arguments:
            claims      (list): Token payload claims.
            expiration  (datetime.timedelta):  Timedelta.

        Response:
            payload   (dict):  JWT payload.
    """

    payload = {}

    for c in claims:

        if c == 'identity':
            payload[c] = 'token_subject'

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
            payload[c] = 'token_issuer'

        elif c == 'exp':
            payload[c] = datetime.datetime.utcnow() + expiration

        elif c == 'iat':
            payload[c] = datetime.datetime.utcnow()

        elif c == 'nbf':
            payload[c] = datetime.datetime.utcnow()

        elif c == 'custom_nbf':
            payload['nbf'] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

        elif c == 'jti':
            payload[c] = 'json_token_identifier'

        else:
            payload[c] = 'custom_claim'

    return payload


def append_custom_header(token, header):
    """
        Changes JWT header.

        Author:
            Lucas Antognoni

        Arguments:
            token   (bytes):    JWT token.
            header  (str):      New JWT header..

        Response:
            forged_token (str): Tempered token.
    """

    split_token = token.split(b'.')

    forged_token = header + b'.' + split_token[1] + b'.' + split_token[2]

    return forged_token
