.. _nuts-auth-jwt-token:

Nuts Auth JWT specification
===========================

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

Sub
---
The subject must be the urn of the legal entity which private key was used in the signature.

Custodian selection
-------------------

For now, this will use the header **X-Nuts-Custodian** with the urn based value.
