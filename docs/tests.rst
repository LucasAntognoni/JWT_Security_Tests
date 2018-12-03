Tests
=====

    The following tests were implemented:

    * `None` algorithm header
    * RS256 Public-Key as HS256 Secret
    * Missing registered claims in payload
    * Missing library claims in payload
    * Missing private claims in payload
    * Expired token
    * Not yet valid token

    The goal is to see what the library offers as tools for verifying the JWT tokens. Covering from the most basic
    (and obvious) pentests to more sophisticated and tricky ones.


None algorithm header
#####################

    This attack occurs when the JWT header `alg` field is changed to `None` and the target system validates the token
    granting access to the attacker. In this scenario, the system does not enforce a signing algorithm nor does it
    checks if the field value matches the one that it is supposed to be using.

    When we send this tempered token to the protected endpoint, the extension checks the app configuration for a defined
    symmetric algorithm and its secret key (HS256) or public key (RSA256). If no algorithm is set, the library uses
    HS256 as default (and throws an error if no secret is set).

    Therefore the forged token won't be validated and no access wil be granted to the attacker using this method.


RS256 Public-Key as HS256 Secret
################################

    This method, in particular, presumes that the attacker had access to the public key used in token validation and, to
    get access, a new token is forged using the key as a secret for the HS256 algorithm. Thus the JWT is signed and the
    header `alg` field is set to HS256.

    If the system does not enforce the RSA256 algorithm and also checks the token header or it depends on this same
    header to determine which verification algorithm it must use, the attacker will pass the decode function and
    validate the forged token.

    The library lets the programmer fix an algorithm, consequently the attacker won't be able to use the forged token as
    it's header `alg` field will not match with the ones currently in use.


Missing registered claims in payload
####################################

    For this test some of the recommended claims, such as `iss`, `exp`, `nbf`, `iat` and `jti` where removed from the
    payload and the encoded token sent to the protected endpoint.

    Tests showed that only when the `jti` claim was removed from the JWT, it was considered invalid by the authorizer,
    while removing any of the remaining ones the token was still valid.

    Thus the library does not check if these claims are in the payload, only if oriented to do so.


Missing library claims in payload
#################################

    The library determines some mandatory claims: `fresh`, `type` and `identity`. The first one says to the extension if
    the token is fresh or not, the second one defines the token type: `access` or `refresh`. The last one, `identity`,
    identifies the subject of the JWT (equivalent to the registered claim `sub`).

    If any of these claims were removed from the payload, the JWT was blocked by the authorizer.


Missing private claims in payload
#################################

    Producers and consumers of JWTs may use claims that are not registered in the IANA "JSON Web Token Claims" registry,
    thus a custom claim was created (`org_id`) and used to verify if the library offered tools to validate or check them.

    The programmer can define a function to verify if the custom claims are in the token payload, but the their data
    validation must be done manually.


Expired token
#############

    Simple test to check if the library validates a expired token. The `exp` field is verified only if it is passed in
    the token payload.


Not yet valid token
###################

    Simple test to check if the library authorizes a token not yet valid for use. The field is not verified by the
    extension and the token is considered valid.


Conclusion
##########

    We can see that the python library gives the user freedom to choose what rules will be used to authorize and verify
    a JWT. It offers some tools that make it easier to set them in code and shield the system from the attacks listed above.

    One thing to notice tough is that the extension uses the `PyJWT` library to encode and decode tokens. And in the tests i
    used this same package to generate tokens. But to create a forged token for "RS256 Public-Key as HS256 Secret" test,
    i had to alter it's code, so i could get a token signed with the public key as a HS256 secret.

    This change was done because the library forbid the use of public keys and certificates as secrets for HMAC algorithm.