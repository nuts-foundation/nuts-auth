.. _nuts-auth-jwt-token:

Nuts Auth JWT specification
===========================

The JWT is specified as:

.. code-block:: json

    {
        "iss": "urn:oid:2.16.840.1.113883.2.4.6.1:48000000",
        "sub": "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
        "aud": "https://target_token_endpoint",
        "usi": {...irma based signature...},
        "osi": {...hardware token sig...},
        "con": {...additional context...},
        "ccn": "CN=client_common_name",
        "icn": "CN=issuer_common_name",
        "exp": max(time_from_irma_sign, some_limited_time),
        "iat": "",
        "jti": {unique-identifier}
    }

`according to rfc7523 <https://tools.ietf.org/html/rfc7523>`_

Iss
---
The issuer in the JWT is always the actor, thus the care organization doing the request.
This iss used to find the public key of the issuer from the Nuts registry.

.. note::
Since the nuts token is signed with the private key of the requester, it is not trivial to verify the signature of the token.
When recieving a request, any token signature verification steps must be postponed until it is clear a token is not a nuts token.

Sub
---
The subject contains the urn of the custodian. The custodian information is used to find the relevant consent (together with actor and subject).

Aud
---
As per `rfc7523 <https://tools.ietf.org/html/rfc7523>`_, the aud must be the token endpoint. This can be taken from the Nuts registry.

Usi
---
User signature. This is the Irma signature presented to the user. Base64 encoded.

Osi
---
Ops signature, optional signature coming from a hardware token, indicating the user belongs to the issuer organization. Can be linked to the Nuts registry.

Con
---
Base64 encoded json representing key-value pairs for additional context for the requested access token. Such as patient and/or task flow selection.

Ccn
---
Client certificate common name. The CN from the client certificate used for the TLS connection which was used for making the request.

Icn
---
Common name of the issuer of the ccn. This certificate must be direct verifiable with the Nuts CA tree.

Exp
---
Expiration, should be set relatively short since this call is only used to get an access token. Must not be bigger than the validity of the Nuts signature validity.

Iat
---
Issued at

Jti
---
Unique identifier, secure random number to prevent replay attacks. The authorization server must check this!