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

from views.rest import restapi
app.register_blueprint(restapi)