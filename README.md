# JSON Web Tokens Pentesting


This project aims to study and test the security of [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io)
python library. As the name says, it adds support for using JSON Web Tokens to
[Flask](https://http://flask.pocoo.org/) in order to protect specific views.

It implements a basic application with a single protected route that will be responsible for validating the tokens
during the tests routines.The tests where developed based on the JWT known vulnerabilities and best practices. 

## References

### Normative

[[RFC7515](https://tools.ietf.org/html/rfc7515)] Jones, M., Bradley, J. and N. Sakimura, "JSON Web Signature (JWS)", RFC 7515, DOI 10.17487/RFC7515, May 2015.

[[RFC7516](https://tools.ietf.org/html/rfc7516)] Jones, M. and J. Hildebrand, "JSON Web Encryption (JWE)", RFC 7516, DOI 10.17487/RFC7516, May 2015.

[[RFC7518](https://tools.ietf.org/html/rfc7518)] Jones, M., "JSON Web Algorithms (JWA)", RFC 7518, DOI 10.17487/RFC7518, May 2015.

[[RFC7519](https://tools.ietf.org/html/rfc7519)] Jones, M., Bradley, J. and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, DOI 10.17487/RFC7519, May 2015.


### Informative

[[Langkemper](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)] Langkemper, S., "Attacking JWT Authentication", September 2016.

[[Sheffer](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-04)] Sheffer, Y., Hardt, D. and Jones, M. B., "JSON Web Token Best Current Practices", Internet-Draft draft-ietf-oauth-jwt-bcp-04, November 2018.

[[Oftedal](https://www.owasp.org/index.php/REST_Security_Cheat_Sheet#JWT)] Oftedal, E. et al. "REST Security Cheat Sheet", September 2018.

[[Peyrott](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)]    Peyrott, S. "A Look at The Draft for JWT Best Current Practices", April 2018.