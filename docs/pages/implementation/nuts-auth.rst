.. _nuts-oauth-implementation:

Nuts OAuth implementation manual
################################

The Nuts OAuth flow is designed to get an access token from the custodian. The authorization server of the custodian will issue an access token if a valid bearer token with a valid signed contract is presented. The Nuts RFCs specify which means can be used to sign the contract. `RFC002 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc002-authentication-token>`_ and `RFC003 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc003-oauth2-authorization>`_ specify the supported means and the OAuth flow.

The Nuts OAuth flow consists of 4 steps:

- constructing a formatted contract
- offer contract for signing to user
- construct bearer token using signed contract
- retrieve access token from authorization server of custodian

Constructing a formatted contract
*********************************

The current contract to use depends on the bolt that is to be used. Let's use the care insight bolt as an example. It uses the following contract:

.. code-block::

    EN:PractitionerLogin:v3 I hereby declare to act on behalf of {{LegalEntityAttr}}. This declaration is valid from {{ValidFromAttr}} until {{ValidToAttr}}.

The ``EN:PractitionerLogin:v3`` part defines the **language**, **type** and **version**. The dutch version of the given contract would be ``NL:BehandelaarLogin:v3``.

You can draw up a contract by calling:

.. code-block::

    POST /internal/auth/experimental/contract/drawup HTTP/1.1
    Host: server.example.com
    Content-Type: application/json

    {
        "type": "PractitionerLogin",
        "language": "EN",
        "version": "v3",
        "legalEntity": "urn:oid:2.16.840.1.113883.2.4.6.1:000000001",
        "validFrom": "2019-06-24T14:32:00+02:00",
        "validDuration": "2h"
    }

The ``legalEntity`` field contains the identifier of the care organization the user is currently representing. Please check the `Nuts Auth API`_ spec for the specifics.

This will return a filled contract where the **legalEntity** has been transformed to the correct organization name:

.. code-block::

    {
        "type": "PractitionerLogin",
        "language": "EN",
        "version": "v3",
        "message": "EN:PractitionerLogin:v3 I hereby declare to act on behalf of Nursing home A. This declaration is valid from Monday, 24 June 2019 14:32:00 until Monday, 24 June 2019 16:32:00."
    }

The ``message`` part will have to used in the next step.

User signature
**************

The ``message`` part of the previous step needs to be presented to the user. The user can sign it using one of the supported means. The following steps use the *dummy* means as example.

Most of the means require the same steps:

- start a session at the means backend
- expose the session data to a user controlled device
- poll the means backend of session updates
- retrieve user signature upon success

A session can be started by doing the following request:

.. code-block::

    POST /internal/auth/experimental/signature/session HTTP/1.1
    Host: server.example.com
    Content-Type: application/json

    {
      "means": "dummy",
      "payload": "EN:PractitionerLogin:v3 I hereby declare to act on behalf of Nursing home A. This declaration is valid from Monday, 24 June 2019 14:32:00 until Monday, 24 June 2019 16:32:00."
    }

As you can see, the ``payload`` is the same as the ``message`` from the *drawup* step. The ``means`` must state the desired means. Next to the specified means in `RFC002 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc002-authentication-token>`_, the Nuts OS implementation also supports a *dummy* means which always succeeds. The *dummy* means is not usable in *strict* mode.

The result contains information on how to present a challenge to the user. In the case of the *dummy* means this is not needed. The result also contains a ``sessionID`` which can be used to poll the status and a ``sessionPtr`` which contains means specific information about the challenge.

.. code-block::

    {
      "means": "dummy",
      "sessionID": "490385cjalwe9587fahnly6fdu8j5r6lndr",
      "sessionPtr": "not used"
    }

With the ``sessionID`` the current status of the signing session can be retrieved:

.. code-block::

    GET /internal/auth/experimental/signature/session/490385cjalwe9587fahnly6fdu8j5r6lndr HTTP/1.1
    Host: server.example.com

returns:

.. code-block::

    {
      "status": "created",
      "verifiablePresentation": "490385cjalwe9587fahnly6fdu8j5r6lndr"
    }

The ``status`` field returns means specific statuses, please consult the documentation of each means to find out what statuses are returned. The ``verifiablePresentation`` field will be filled when the session has been completed and the user has successfully signed the contract. The contents of the ``verifiablePresentation`` field is BASE64 encoded and conforms to `RFC002 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc002-authentication-token>`_.

Bearer token
************

The previous paragraph showed us how to get a signed contract in the form of a *verifiable presentation*. The *verifiable presentation* can be used to create a bearer token by calling:

.. code-block::

    POST /auth/jwtbearertoken HTTP/1.1
    Host: server.example.com
    Content-Type: application/json

    {
      "custodian": "urn:oid:2.16.840.1.113883.2.4.6.1:000000002",
      "actor": "urn:oid:2.16.840.1.113883.2.4.6.1:000000001",
      "subject": "urn:oid:2.16.840.1.113883.2.4.6.3:999999990"
      "identity": "eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJwcm9vZiI6eyJCaXJ0aGRhdGUiOiIxOTgwLTAxLTAxIiwiQ29udHJhY3QiOiJFTjpQcmFjdGl0aW9uZXJMb2dpbjp2MyBJIGhlcmVieSBkZWNsYXJlIHRvIGFjdCBvbiBiZWhhbGYgb2YgT3JnIEIuIFRoaXMgZGVjbGFyYXRpb24gaXMgdmFsaWQgZnJvbSBkaW5zZGFnLCAxIGRlY2VtYmVyIDIwMjAgMTE6NDA6NTYgdW50aWwgZGluc2RhZywgMSBkZWNlbWJlciAyMDIwIDEyOjQwOjU2LiIsIkVtYWlsIjoidGVzdGVyQGV4YW1wbGUuY29tIiwiSW5pdGlhbHMiOiJJIiwiTGFzdG5hbWUiOiJUZXN0ZXIiLCJUeXBlIjoiTm9TaWduYXR1cmUifSwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwiRHVtbXlWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl19Cg==",
      "scope": "nuts"
    }

The ``scope`` field must be **nuts** according to spec and the ``identity`` field must be filled with the contents of the ``verifiablePresentation`` of the previous paragraph. The ``actor`` field must be filled with the *identifier* of the care organization the current user is representing. It must be the same as used in `Constructing a formatted contract`_. The *identifier* for the ``custodian`` field must have been obtained by other means. It can, for example, come from a registered consent record which granted this actor access to data at the custodian given a certain subject. The ``subject`` field is optional, when used it must identify a patient. ``urn:oid:2.16.840.1.113883.2.4.6.3:999999990`` is the Dutch citizen number ``999999990``.

If the identifiers match with the contract, a bearer token in the form of a JWT is returned:

.. code-block::

    {
      "bearer_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDZ0RDQ0FXaWdBd0lCQWdJUkFLT21reVp5Z2lBRXFMeUt1T3JnKzNjd0RRWUpLb1pJaHZjTkFRRUxCUUF3TmpFTE1Ba0dBMVVFQmhNQ1Rrd3hFVEFQQmdOVkJBb1RDRlpsYm1SdmNpQkNNUlF3RWdZRFZRUURFd3RXWlc1a2IzSWdRaUJEUVRBZUZ3MHlNREV5TURFeE1EUXdOVFphRncweU1ERXlNRFV4TURRd05UWmFNRGt4Q3pBSkJnTlZCQVlUQWs1TU1SRXdEd1lEVlFRS0V3aFdaVzVrYjNJZ1FqRVhNQlVHQTFVRUF4TU9WbVZ1Wkc5eUlFSWdiMkYxZEdnd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSOUxvREF4clVTM1NxM2I4akZmakdmOE5IUXR2ODBwWXFobENhaEd0djRjM0w3a1M3c1BmR0I4VjZ5WkNZVURyWXU5ZUdWcEJFQUtBL0MwWnNUWHhsWm8xRXdUekFPQmdOVkhROEJBZjhFQkFNQ0JzQXdJZ1lEVlIwUkJCc3dHYUFYQmdrckJnRUVBWU9zUXdTZ0Nnd0lNREF3TURBd01ESXdHUVlKS3dZQkJBR0RyRU1EQkF3TUNtaGxZV3gwYUdOaGNtVXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQlNSVTNGKys4VUsvOEthVHBBWGZUOHUxd0t6ZFpEUDB5NTNNNTZET2xqK0JmaWNsd0h0Rlc2VmhvTU5sSXBUU1NCUWkxS0hKZWZnVUlGNStRd0lDbE9jeDNheDNldzJBVVNEVWdURnBiS2pETzF3VjhCWWw4dGdjdjkzc2NNZ0pTM09ZeGZnY1VQZ1AvVEZMK1R2SVNMb3pWcURBOGVTMDUyREdEM0MvbS80QjVKZEVkYU9tSVdTdzk2Z1g2LzYrTHI4TUJHWGp6aEFKa2RXcmEzeUhDS2R4ME4xSVpkUW53SnZacG02ZVRpTkhSbHgyQUkrMTVpVXdNaWdlTlhSazhzNFEybG9vb2FIUWhtcWpXSTU4Z3ZHa1l3YmZ3Yk91b2UrRFdLQ2xWMkJnZjcvanlwRU9JTUhNYS9SV0RzUHhxdy9iT3FRaDBwZ3BwRU82TzFHQytBPSJdfQ.eyJTaWduaW5nQ2VydGlmaWNhdGUiOm51bGwsImF1ZCI6IjRlYjlmNDM4LTc4MWQtNDU5NC04NTMxLTNiODgxOTc1MWM4YyIsImV4cCI6MTYwNjgxOTI2MSwiaWF0IjoxNjA2ODE5MjU2LCJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6QiIsInNjb3BlIjoiIiwic2lkIjpudWxsLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6QSIsInVzaSI6ImV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNKZExDSndjbTl2WmlJNmV5SkNhWEowYUdSaGRHVWlPaUl4T1Rnd0xUQXhMVEF4SWl3aVEyOXVkSEpoWTNRaU9pSkZUanBRY21GamRHbDBhVzl1WlhKTWIyZHBianAyTXlCSklHaGxjbVZpZVNCa1pXTnNZWEpsSUhSdklHRmpkQ0J2YmlCaVpXaGhiR1lnYjJZZ1QzSm5JRUl1SUZSb2FYTWdaR1ZqYkdGeVlYUnBiMjRnYVhNZ2RtRnNhV1FnWm5KdmJTQmthVzV6WkdGbkxDQXhJR1JsWTJWdFltVnlJREl3TWpBZ01URTZOREE2TlRZZ2RXNTBhV3dnWkdsdWMyUmhaeXdnTVNCa1pXTmxiV0psY2lBeU1ESXdJREV5T2pRd09qVTJMaUlzSWtWdFlXbHNJam9pZEdWemRHVnlRR1Y0WVcxd2JHVXVZMjl0SWl3aVNXNXBkR2xoYkhNaU9pSkpJaXdpVEdGemRHNWhiV1VpT2lKVVpYTjBaWElpTENKVWVYQmxJam9pVG05VGFXZHVZWFIxY21VaWZTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxVSEpsYzJWdWRHRjBhVzl1SWl3aVJIVnRiWGxXWlhKcFptbGhZbXhsVUhKbGMyVnVkR0YwYVc5dUlsMTlDZz09In0.b-HfO25rqmMusqFGxXiZ645bKvgZTfJL11er_Fm1Svc7gcubhGkWSOR9zuNdW_nYHwTDQI4z7pVkUqgdEd-BhA"
    }

This bearer token can be used to get an access token at the custodian side.

Access token
************

The access token is issued by the authorization server at the custodian side. According to spec it may be anything as long as it's BASE64 encoded and it can fit in a HTTP header. The authorization server embedded in the Nuts OS implementation uses JWTs as access tokens.

To get an access token, perform the following steps:

- find the authorization server endpoint
- retrieve the access token
- use the access token

One way of obtaining the right endpoint is to use the Nuts registry. The Nuts registry holds OAuth endpoints for each vendor, care organization and service combination.

.. note::

    This is work in progress. The API hasn't been defined yet on the registry.

We'll use the access token endpoint on the Nuts OS implementation as reference endpoint:

.. code-block::

    POST /auth/accesstoken HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
    &assertion=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI...WSOR9zuNdW_nYHwTDQI4z7pVkUqgdEd-BhA

the ``grant-type`` is fixed and equals **urn:ietf:params:oauth:grant-type:jwt-bearer**. The ``assertion`` is the **bearer token** from the previous paragraph. This request must be send over TLS and the sender must use a **client certificate**. `RFC003 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc003-oauth2-authorization>`_ and `RFC008 <https://nuts-foundation.gitbook.io/drafts/rfc/rfc008-certificate-structure>`_ specify the requirements for the client certificate. The Nuts OS implementation contains a convenient endpoint for getting a client certificate signed by the vendor CA:

.. code-block::

    POST /crypto/certificate/tls HTTP/1.1
    Host: server.example.com
    Content-Type: application/octet-stream

    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExr9OdS3meIrzaqNMi+RWIT5v4hcA
    AJwvfhf8Wy+jh97W8fPGwVZvUcRTrSESvGBV+kas4pd+K4E335Ifd1+XIg==
    -----END PUBLIC KEY-----

The result will be the client certificate in pem encoding. The client is responsible for the storage of the key material. If the authorization server accepts the bearer token it'll return an access token:

.. code-block::

    {
        "access_token":"2YotnFZFEjr1zCsicMWpAA",
        "token_type":"bearer",
        "expires_in":60
    }

The access token can now be used for 60 seconds in a normal ``Authorization`` header as:

.. code-block::

    GET /fhir/Patient HTTP/1.1
    Host: server.example.com
    Authorization: bearer 2YotnFZFEjr1zCsicMWpAA

As explained earlier, it's up to the authorization server to determine the access token content. The Nuts OS implementation uses JWTs with the following contents:

.. code-block::

    {
        "alg": "PS256",
        "typ": "JWT"
    }
    {
        "email": "tester@example.com",
        "exp": 1606820157,
        "family_name": "tester",
        "given_name": "test",
        "iat": 1606819257,
        "iss": "urn:oid:2.16.840.1.113883.2.4.6.1:00000002",
        "name": "test tester",
        "prefix": "",
        "scope": "",
        "sub": "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"
    }
    {
        ...signature omitted
    }
