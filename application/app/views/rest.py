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

Implementation
==============
"""

import sys
sys.path.extend(['/home/lucas/Git/JWT_Security_Tests'])

from app import jwt
from flask_jwt_extended import jwt_required, get_raw_jwt, create_access_token
from flask import Blueprint, jsonify, request

restapi = Blueprint('restapi', __name__)


# TOKEN ERROR CALLBACKS
@jwt.unauthorized_loader
def unauthorized_response(callback):
    """
        Unauthorized token callback.

        Author:
            Lucas Antognoni

        Arguments:
            callback (function): The method callback function.

        Response:
            json
                {
                    'error': (boolean),
                    'message': (str)
                }

        Response keys:

            - 'error': True.
            - 'message': Error message.
    """

    return jsonify({
        'error': True,
        'message': 'Missing Authorization Header'
    }), 401


@jwt.expired_token_loader
def expired_response():
    """
        Expired token callback.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            json
                {
                    'error': (boolean),
                    'message': (str)
                }

        Response keys:

            - 'error': True.
            - 'message': Error message.
    """

    return jsonify({
        'error': True,
        'message': 'Token has expired'
    }), 401


@jwt.invalid_token_loader
def invalid_response(callback):
    """
        Invalid token callback.

        Author:
            Lucas Antognoni

        Arguments:
            callback (function): The method callback function.

        Response:
            json
                {
                    'error': (boolean),
                    'message': (str)
                }

        Response keys:

            - 'error': True.
            - 'message': Error message.
    """

    return jsonify({
        'error': True,
        'message': 'Token is invalid'
    }), 401


@jwt.claims_verification_failed_loader
def claims_response():
    """
        Invalid claims callback.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            json
                {
                    'error': (boolean),
                    'message': (str)
                }

        Response keys:

            - 'error': True.
            - 'message': Error message.
    """

    return jsonify({
        'error': True,
        'message': 'Invalid token claims'
    }), 401


# CLAIMS VERIFICATION
@jwt.claims_verification_loader
def verify_claims(claims):
    """
        Token claims verifier.

        Author:
            Lucas Antognoni

        Arguments:
            claims (dict): JWT claims dict

        Response:
            valid (boolean): True if valid, False o/w.
    """

    if 'org_id' in claims:
        return False
    else:
        return True


@restapi.route('/protected', methods=['GET'])
@jwt_required
def protected():
    """
        Protected endpoint for testing.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            json
                {
                    'error': (boolean),
                    'message': (str)
                }

        Response keys:

            - 'error': False.
            - 'message': Success message.
    """

    return jsonify({
        'error': False,
        'message': 'Valid token.'
    }), 200

