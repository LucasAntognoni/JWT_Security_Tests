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

Implementation
==============
"""

import sys
sys.path.extend(['/home/lucas/Git/JWT_Security_Tests'])

from app import jwt
from flask_jwt_extended import jwt_required, get_raw_jwt, create_access_token
from flask import Blueprint, abort, jsonify, url_for, Flask, request, Response


restapi = Blueprint('restapi', __name__)


# TOKEN ERROR CALLBACKS START

@jwt.unauthorized_loader
def unauthorized_response():
    """
        Unauthorized token callback.

        Author:
            Lucas Castro

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
            Lucas Castro

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
def invalid_response():
    """
        Invalid token callback.

        Author:
            Lucas Castro

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

# TOKEN ERROR CALLBACKS END


# BASIC ROUTES START

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

# BASIC ROUTES START
