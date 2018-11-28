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
+-----------------+------------------------------------------------------------------------+
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

import sys
sys.path.extend(['/home/lucas/Git/JWT_Security_Tests'])

import json
import requests

from datetime import timedelta
from common.jwt import create_token, custom_header, custom_payload, append_custom_header


JWT_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHuPWRxAWbRQRij4/tWmfstd5gFL\nO3Er2QrwoqEb2W98oOnLcyhxxdVDKhXtcnr1/H1WsTXS6aFNYk+9U8TIzmKtczKk\nWKYttzc28kNOX+Ia+mOSB7ENYu1xA3FY9tKNS7PD/SOhKGEYcYzWbvX8Eiy8oGcb\n3/Yy7MnpmOFO1PF/AgMBAAE=\n-----END PUBLIC KEY-----'
JWT_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgHuPWRxAWbRQRij4/tWmfstd5gFLO3Er2QrwoqEb2W98oOnLcyhx\nxdVDKhXtcnr1/H1WsTXS6aFNYk+9U8TIzmKtczKkWKYttzc28kNOX+Ia+mOSB7EN\nYu1xA3FY9tKNS7PD/SOhKGEYcYzWbvX8Eiy8oGcb3/Yy7MnpmOFO1PF/AgMBAAEC\ngYBsO+WTGct6Z9cNjQ+tl2r6OgaAm6Y2PHKjYqcS+ZI+Vq2eHtmBVCg3592114mw\nrEnAgXA59ccxxNeZgf8fIcem6aj+xzXZoPXDiRw9EPSmQEYAjEVCq40uvt+Tl+j+\n7OOND5FF2V2Y89mxUUmiO6xLrkjb2NqN86KEOC/VgbDaAQJBAN2CnpP4YZN7dijJ\nNyRV+UKLc+MO5hq02yBXvnwEYG1xYXinr4ZX4eqsTbWT6AH8BGFDNq+hI8fKYOHz\nr72FEXUCQQCOzHAsrlHqE1m/P9oEty8aKZTYnR01rWIsE4AZwGZTWw/awKq16WMh\n1+q+s7nC8Lzt90H3j7OIUGUzXTZ74QSjAkASzlAgR+og106Ez/B6iUIMQEKqeE1Y\n3xnreQeXB9gX8pRP5gyk3zky70X5sID2CitlBovSBWBAShJHnKTC9lUxAkA0Bo3T\n6YrUkko/YH8I+siBaqbdKJjMxqee0Vf5idx+AA5Nr6ZCco54dRcEdax3NohO1qfF\nDyjkwA2u4gYIqhmrAkB2ESXa2QD/rrD4r9FFT1YPYjmLi27lkqxe24fOKTsdGqvj\nqGfEkU9AWx6AJN0H/1sMhkpMkXvLplLN+opoF/Id\n-----END RSA PRIVATE KEY-----'


def test_result_formatting(response):
    response_json = response.decode('utf8').replace("'", '"')
    data = json.loads(response_json)
    result = json.dumps(data, indent=4, sort_keys=True)

    return result


def send_request(token):

    url = 'http://127.0.0.1:8080/protected'
    headers = {'Authorization': (b'Bearer ' + token).decode("utf-8")}

    r = requests.get(url, headers=headers)

    return r


def none_algorithm_test():

    print('\n<<<<<<<<<< None algorithm test >>>>>>>>>>\n')

    claims = ['identity', 'org_id', 'access', 'fresh', 'iss', 'exp', 'iat', 'nbf', 'jti']
    payload = custom_payload(claims, timedelta(hours=2))

    header = custom_header('none', 'JWT')

    token = create_token(payload, JWT_PRIVATE_KEY, 'RS256')

    forged_token = append_custom_header(token, header)

    response = send_request(forged_token)

    print(test_result_formatting(response.content))

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


def rs_to_hs_algorithm_test():

    print('\n<<<<<<<<<< RS256 to algorithm test >>>>>>>>>>\n')

    claims = ['identity', 'org_id', 'access', 'fresh', 'iss', 'exp', 'iat', 'nbf', 'jti']
    payload = custom_payload(claims, timedelta(hours=2))

    header = custom_header('HS256', 'JWT')

    token = create_token(payload, JWT_PUBLIC_KEY, 'HS256')

    print(token)

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


def missing_registered_claims_tests():

    print('\n<<<<<<<<<< Missing registered claim test >>>>>>>>>>\n')

    claims = ['identity', 'org_id', 'access', 'fresh', 'iss', 'exp', 'iat', 'nbf', 'jti']

    print("No claim removed.")

    while len(claims) > 3:

        # print(claims)

        payload = custom_payload(claims, timedelta(hours=2))

        token = create_token(payload, JWT_PRIVATE_KEY, 'RS256')

        # print(token)
        # print()

        response = send_request(token)

        print(test_result_formatting(response.content))

        print("\nRemoved claim: %s." % claims.pop())

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


def missing_public_claims_tests():

    print('\n<<<<<<<<<< Missing public claim test >>>>>>>>>>\n')

    claims = ['org_id', 'iss', 'exp', 'iat', 'nbf', 'jti', 'identity', 'access', 'fresh']

    print("No claim removed.")

    while len(claims) > 5:

        # print(claims)

        payload = custom_payload(claims, timedelta(hours=2))

        token = create_token(payload, JWT_PRIVATE_KEY, 'RS256')

        # print(token)
        # print()

        response = send_request(token)

        print(test_result_formatting(response.content))

        print("\nRemoved claim: %s." % claims.pop())

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


def missing_private_claim_test():

    print('\n<<<<<<<<<< Missing private claim test >>>>>>>>>>\n')

    claims = ['identity', 'access', 'fresh', 'iss', 'exp', 'iat', 'nbf', 'jti']
    payload = custom_payload(claims, timedelta(hours=2))

    token = create_token(payload, JWT_PRIVATE_KEY, 'RS256')

    # print(token)
    # print()

    response = send_request(token)

    print(test_result_formatting(response.content))

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


none_algorithm_test()
# rs_to_hs_algorithm_test()
missing_registered_claims_tests()
missing_public_claims_tests()
missing_private_claim_test()
