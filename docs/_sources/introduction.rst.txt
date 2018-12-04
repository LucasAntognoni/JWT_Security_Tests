Introduction
============

    This project aims to study and test the security of `Flask-JWT-Extended <https://flask-jwt-extended.readthedocs.io>`_
    python library. As the name says, it adds support for using JSON Web Tokens to
    `Flask <https://http://flask.pocoo.org/>`_, in order to protect specific views.

    It implements a basic application with a single protected route that will be responsible for validating the tokens
    during the tests routines.

    The tests where developed based on the JWT known vulnerabilities and best practices shown in the following
    references:

    **Normative**

    .. [RFC7515]	Jones, M., Bradley, J. and N. Sakimura, `"JSON Web Signature (JWS)" <https://tools.ietf.org/html/rfc7515>`_, RFC 7515, DOI 10.17487/RFC7515, May 2015.

    .. [RFC7516]	Jones, M. and J. Hildebrand, `"JSON Web Encryption (JWE)" <https://tools.ietf.org/html/rfc7516>`_, RFC 7516, DOI 10.17487/RFC7516, May 2015.

    .. [RFC7518]	Jones, M., `"JSON Web Algorithms (JWA)" <https://tools.ietf.org/html/rfc7518>`_, RFC 7518, DOI 10.17487/RFC7518, May 2015.

    .. [RFC7519]	Jones, M., Bradley, J. and N. Sakimura, `"JSON Web Token (JWT)" <https://tools.ietf.org/html/rfc7519>`_, RFC 7519, DOI 10.17487/RFC7519, May 2015.

    **Informative**

    .. [Langkemper] Langkemper, S., `"Attacking JWT Authentication" <https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/>`_, September 2016.

    .. [Sheffer]    Sheffer, Y., Hardt, D. and Jones, M. B., `"JSON Web Token Best Current Practices" <https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-04>`_,Internet-Draft draft-ietf-oauth-jwt-bcp-04, November 2018.

    .. [Oftedal]    Oftedal, E. et al. `"REST Security Cheat Sheet" <https://www.owasp.org/index.php/REST_Security_Cheat_Sheet#JWT>`_, September 2018.

    .. [Peyrott]    Peyrott, S. `"A Look at The Draft for JWT Best Current Practices" <https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/>`_, April 2018.