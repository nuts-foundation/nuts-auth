.. _nuts-auth-jwt-token:

Nuts Auth JWT specification
===========================

The JWT is specified as:

.. code-block:: json

    {
        "iss": "urn:oid:2.16.840.1.113883.2.4.6.1",
        "sig": base64 encoded signature
        "type": type of the encoded signature
    }

Iss
---
The issuer contains the urn of the requestor (actor). The token has been signed with the private key of the requestor.
This is to make sure that a token cannot be reused be any other party to make requests in the Nuts network.

.. note::

    Since the nuts token is signed with the private key of the requester, it is not trivial to verify the signature of the token.
    When recieving a request, any token signature verification steps must be postponed until it is clear a token is not a nuts token.

Sig
---
The signature contains a base64 encoded string. The `type` attribute determines the content of this signature.

Custodian selection
-------------------

A single API endpoint can provide access to the data of multiple care providers (e.g. a multi-tanant SaaS).
Therefor, when requesting data, an actor needs to provide the custodian of the data it wants to request.
For now, an actor must provide the **X-Nuts-Custodian** header with the urn based value in the request.

Nuts Auth JWT specification (Legacy)
====================================

.. note::

    this specification is for the JWT used in version <= 0.13.

The JWT is specified as:

.. code-block:: json

    {
        "iss": "nuts",
        "sub": "urn:oid:2.16.840.1.113883.2.4.6.1",
        "nuts_signature": {...irma based signature...}
    }

Iss
---
The issuer in the JWT is always *nuts*.
This allows the API of the care provider to switch between validation mechanisms:
When the Issuer is *nuts* post the token to the token check endpoint, if not, do your usual checks.

.. note::

    Since the nuts token is signed with the private key of the requester, it is not trivial to verify the signature of the token.
    When recieving a request, any token signature verification steps must be postponed until it is clear a token is not a nuts token.

Sub
---
The subject contains the urn of the requestor (actor). The token has been signed with the private key of the requestor.
This is to make sure that a token cannot be reused be any other party to make requests in the Nuts network.

Custodian selection
-------------------

A single API endpoint can provide access to the data of multiple care providers (e.g. a multi-tanant SaaS).
Therefor, when requesting data, an actor needs to provide the custodian of the data it wants to request.
For now, an actor must provide the **X-Nuts-Custodian** header with the urn based value in the request.
