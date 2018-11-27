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

import sys
sys.path.extend(['/home/lucas/Git/JWT_Security_Tests'])

from .. import app
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


# TOKEN VERIFICATION
@jwt.claims_verification_loader
def verify_claims(claims):
    """
        Token claims verifier.

        Author:
            Lucas Antognoni

        Arguments:
            claims (dict): JWT claims dict

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

    if 'org_id' in claims:
        return True
    else:
        return False


# BASIC ROUTES
@restapi.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    if username != 'test' or password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200


@restapi.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify(payload=get_raw_jwt()), 200

