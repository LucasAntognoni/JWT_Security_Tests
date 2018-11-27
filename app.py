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

from flask import Flask
from flask_jwt_extended import JWTManager

from config import config

app = Flask(__name__)
config_name = 'development'
app.config.from_object(config[config_name])
instance_path = app.root_path

jwt = JWTManager(app)

from rest import restapi
app.register_blueprint(restapi)