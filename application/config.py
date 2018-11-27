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



Implementation
==============
"""

import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

from datetime import timedelta


class Config:

    JWT_ALGORITHM = 'RS256'

    JWT_TOKEN_LOCATION = 'headers'
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'

    JWT_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHuPWRxAWbRQRij4/tWmfstd5gFL\nO3Er2QrwoqEb2W98oOnLcyhxxdVDKhXtcnr1/H1WsTXS6aFNYk+9U8TIzmKtczKk\nWKYttzc28kNOX+Ia+mOSB7ENYu1xA3FY9tKNS7PD/SOhKGEYcYzWbvX8Eiy8oGcb\n3/Yy7MnpmOFO1PF/AgMBAAE=\n-----END PUBLIC KEY-----'
    JWT_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgHuPWRxAWbRQRij4/tWmfstd5gFLO3Er2QrwoqEb2W98oOnLcyhx\nxdVDKhXtcnr1/H1WsTXS6aFNYk+9U8TIzmKtczKkWKYttzc28kNOX+Ia+mOSB7EN\nYu1xA3FY9tKNS7PD/SOhKGEYcYzWbvX8Eiy8oGcb3/Yy7MnpmOFO1PF/AgMBAAEC\ngYBsO+WTGct6Z9cNjQ+tl2r6OgaAm6Y2PHKjYqcS+ZI+Vq2eHtmBVCg3592114mw\nrEnAgXA59ccxxNeZgf8fIcem6aj+xzXZoPXDiRw9EPSmQEYAjEVCq40uvt+Tl+j+\n7OOND5FF2V2Y89mxUUmiO6xLrkjb2NqN86KEOC/VgbDaAQJBAN2CnpP4YZN7dijJ\nNyRV+UKLc+MO5hq02yBXvnwEYG1xYXinr4ZX4eqsTbWT6AH8BGFDNq+hI8fKYOHz\nr72FEXUCQQCOzHAsrlHqE1m/P9oEty8aKZTYnR01rWIsE4AZwGZTWw/awKq16WMh\n1+q+s7nC8Lzt90H3j7OIUGUzXTZ74QSjAkASzlAgR+og106Ez/B6iUIMQEKqeE1Y\n3xnreQeXB9gX8pRP5gyk3zky70X5sID2CitlBovSBWBAShJHnKTC9lUxAkA0Bo3T\n6YrUkko/YH8I+siBaqbdKJjMxqee0Vf5idx+AA5Nr6ZCco54dRcEdax3NohO1qfF\nDyjkwA2u4gYIqhmrAkB2ESXa2QD/rrD4r9FFT1YPYjmLi27lkqxe24fOKTsdGqvj\nqGfEkU9AWx6AJN0H/1sMhkpMkXvLplLN+opoF/Id\n-----END RSA PRIVATE KEY-----'

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=2)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=2)

    # @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False


config = dict(development=DevelopmentConfig,
              testing=TestingConfig,
              production=ProductionConfig,
              default=DevelopmentConfig)
