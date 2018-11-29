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

import json
import requests

from time import sleep
from datetime import timedelta
from common.jwt import create_token, custom_header, custom_payload, append_custom_header


# RSA Keys for testing
JWT_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHuPWRxAWbRQRij4/tWmfstd5gFL\nO3Er2QrwoqEb2W98oOnLcyhxxdVDKhXtcnr1/H1WsTXS6aFNYk+9U8TIzmKtczKk\nWKYttzc28kNOX+Ia+mOSB7ENYu1xA3FY9tKNS7PD/SOhKGEYcYzWbvX8Eiy8oGcb\n3/Yy7MnpmOFO1PF/AgMBAAE=\n-----END PUBLIC KEY-----'
JWT_PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgHuPWRxAWbRQRij4/tWmfstd5gFLO3Er2QrwoqEb2W98oOnLcyhx\nxdVDKhXtcnr1/H1WsTXS6aFNYk+9U8TIzmKtczKkWKYttzc28kNOX+Ia+mOSB7EN\nYu1xA3FY9tKNS7PD/SOhKGEYcYzWbvX8Eiy8oGcb3/Yy7MnpmOFO1PF/AgMBAAEC\ngYBsO+WTGct6Z9cNjQ+tl2r6OgaAm6Y2PHKjYqcS+ZI+Vq2eHtmBVCg3592114mw\nrEnAgXA59ccxxNeZgf8fIcem6aj+xzXZoPXDiRw9EPSmQEYAjEVCq40uvt+Tl+j+\n7OOND5FF2V2Y89mxUUmiO6xLrkjb2NqN86KEOC/VgbDaAQJBAN2CnpP4YZN7dijJ\nNyRV+UKLc+MO5hq02yBXvnwEYG1xYXinr4ZX4eqsTbWT6AH8BGFDNq+hI8fKYOHz\nr72FEXUCQQCOzHAsrlHqE1m/P9oEty8aKZTYnR01rWIsE4AZwGZTWw/awKq16WMh\n1+q+s7nC8Lzt90H3j7OIUGUzXTZ74QSjAkASzlAgR+og106Ez/B6iUIMQEKqeE1Y\n3xnreQeXB9gX8pRP5gyk3zky70X5sID2CitlBovSBWBAShJHnKTC9lUxAkA0Bo3T\n6YrUkko/YH8I+siBaqbdKJjMxqee0Vf5idx+AA5Nr6ZCco54dRcEdax3NohO1qfF\nDyjkwA2u4gYIqhmrAkB2ESXa2QD/rrD4r9FFT1YPYjmLi27lkqxe24fOKTsdGqvj\nqGfEkU9AWx6AJN0H/1sMhkpMkXvLplLN+opoF/Id\n-----END RSA PRIVATE KEY-----'


def test_result_formatting(response):
    """
        Formats the test output.

        Author:
            Lucas Antognoni

        Arguments:
            response (bytes): Protected endpoint response contents.

        Response:
            result (JSON): Response in JSON format.
    """

    response_json = response.decode('utf8').replace("'", '"')
    data = json.loads(response_json)
    result = json.dumps(data, indent=4, sort_keys=True)

    return result


def send_request(token):
    """
        Send request to protected endpoint.

        Author:
            Lucas Antognoni

        Arguments:
            token (bytes): JWT token.

        Response:
            response (requests.models.Response): Request to protected endpoint response.
    """

    url = 'http://127.0.0.1:8080/protected'
    headers = {'Authorization': (b'Bearer ' + token).decode("utf-8")}

    response = requests.get(url, headers=headers)

    return response


def none_algorithm_test():
    """
        None algorithm in token header test.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            prints the output from test.
    """

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
    """
        Encrypt token with public key and change algorithm header to HS256.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            prints the output from test.
    """

    print('\n<<<<<<<<<< RS256 to HS256 algorithm test >>>>>>>>>>\n')

    claims = ['identity', 'org_id', 'access', 'fresh', 'iss', 'exp', 'iat', 'nbf', 'jti']
    payload = custom_payload(claims, timedelta(hours=2))

    header = custom_header('HS256', 'JWT')

    token = create_token(payload, JWT_PUBLIC_KEY, 'HS256')

    response = send_request(token)

    print(test_result_formatting(response.content))

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


def missing_registered_claims_tests():
    """
        Removes JWT registered claims from payload.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            prints the output from test.
    """

    print('\n<<<<<<<<<< Missing registered claim test >>>>>>>>>>\n')

    claims = ['identity', 'org_id', 'access', 'fresh', 'iss', 'exp', 'iat', 'nbf', 'jti']
    to_be_removed = ['iss', 'exp', 'iat', 'nbf', 'jti']

    while len(to_be_removed) > 0:

        element = to_be_removed.pop()

        print("\nRemoved claim: %s." % element)

        claims_ = [x for i, x in enumerate(claims) if x != element]

        print(claims_)

        payload = custom_payload(claims_, timedelta(hours=2))

        token = create_token(payload, JWT_PRIVATE_KEY, 'RS256')

        # print(token)
        # print()

        response = send_request(token)

        print(test_result_formatting(response.content))

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


def missing_public_claims_tests():
    """
        Removes JWT public claims from payload.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            prints the output from test.
    """

    print('\n<<<<<<<<<< Missing public claims test >>>>>>>>>>\n')

    claims = ['org_id', 'iss', 'exp', 'iat', 'nbf', 'jti', 'identity', 'access', 'fresh']
    to_be_removed = ['identity', 'access', 'fresh']

    while len(to_be_removed) > 0:
        element = to_be_removed.pop()

        print("\nRemoved claim: %s." % element)

        claims_ = [x for i, x in enumerate(claims) if x != element]

        print(claims_)

        payload = custom_payload(claims_, timedelta(hours=2))

        token = create_token(payload, JWT_PRIVATE_KEY, 'RS256')

        # print(token)
        # print()

        response = send_request(token)

        print(test_result_formatting(response.content))

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


def missing_private_claim_test():
    """
        Removes JWT private claims from payload.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            prints the output from test.
    """

    print('\n<<<<<<<<<< Missing private claim test >>>>>>>>>>\n')

    claims = ['identity', 'access', 'fresh', 'iss', 'exp', 'iat', 'nbf', 'jti']
    payload = custom_payload(claims, timedelta(hours=2))

    token = create_token(payload, JWT_PRIVATE_KEY, 'RS256')

    # print(token)
    # print()

    response = send_request(token)

    print("Removed claim: org_id")
    print(test_result_formatting(response.content))

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


def expired_token_test():
    """
        Authenticate with expired JWT.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            prints the output from test.
    """
    print('\n<<<<<<<<<< Expired token test >>>>>>>>>>\n')

    claims = ['identity', 'org_id', 'access', 'fresh', 'iss', 'exp', 'iat', 'nbf', 'jti']
    payload = custom_payload(claims, timedelta(hours=0))

    print('10, 9, 8, 7....')
    sleep(10)

    token = create_token(payload, JWT_PRIVATE_KEY, 'RS256')

    response = send_request(token)

    print(test_result_formatting(response.content))

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


def not_before_token_test():
    """
        Authenticate with not yet valid JWT.

        Author:
            Lucas Antognoni

        Arguments:

        Response:
            prints the output from test.
    """

    print('\n<<<<<<<<<< Not before token test >>>>>>>>>>\n')

    claims = ['identity', 'org_id', 'access', 'fresh', 'iss', 'exp', 'iat', 'nbf', 'jti']
    payload = custom_payload(claims, timedelta(hours=2))

    token = create_token(payload, JWT_PRIVATE_KEY, 'RS256')

    response = send_request(token)

    print(test_result_formatting(response.content))

    print('\n<<<<<<<<<<<<<<<<<<<<#>>>>>>>>>>>>>>>>>>>>\n')


if __name__ == '__main__':
    none_algorithm_test()
    rs_to_hs_algorithm_test()
    missing_registered_claims_tests()
    missing_public_claims_tests()
    missing_private_claim_test()
    expired_token_test()
    not_before_token_test()
