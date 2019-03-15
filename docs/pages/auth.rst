Auth Module
===========

The Authentication module enables the :doc:`Vendor space <nuts-documentation:pages/architecture>` to perform operations related to authentication.
We use authentication contracts in which a user gives consent to an acting party to operate on data on its behalves.
See contracts in the main documentation :doc:`nuts-documentation:pages/login-contract`

In an operation between two Nuts nodes there are two roles:
  * The **acting party**: the one who serves its user and makes the request.
  * The **serving party**: the one who serves the data of the patient and reveives the request.

.. figure:: /_static/images/parties-diagram.png
    :align: center
    :alt: Two parties exchanging data
    :figclass: align-center


Create auth contract for user
#############################

In order for a user to query for or operate on data stored in the serving party, the acting party should craft a special token containing a contract signed by the user which proves that the acting party is authorized to perform a query.

.. note::
  Nuts uses `IRMA <https://irma.app/docs/>`_ in the background to sign and verify contracts.

The Nuts proxy provides a convenient endpoint for the *Vendor space* to initiate the signing process.
The acting party chooses the the appropriate contract type and the language.
The in the background IRMA creates a signing session and returns a object with the session information.
The acting party should present this session information in the form of a QR-code to its user who can choose to scan it with its IRMA app and sign the contract.

Since the transaction between the user and IRMA are out of bound, the acting party does not know when the signing is completed or aborted. Therefor it needs to poll for or subscribe to changes in the transaction status.

When the transaction between the user and IRMA completes, the acting party receives the fully signed contract which it can use to make requests to other *serving parties*.
The contract must be sent in the form of a *JWT* with ``nuts`` as the issuer.

.. figure:: /_static/images/irma-login.sequence-diagram.png
    :width: 600px
    :align: center
    :alt: Irma consent login sequence diagram
    :figclass: align-center

.. openapi:: /_static/openapi-spec.yaml
   :paths:
      /auth/contract/{type}
      /auth/contract/session


Validate auth contract from user
################################

When the *serving party* receives a request on its APIs from another *acting party*, it needs to validate the *JWT* and its containing contract.

The Nuts proxy provides a convenient endpoint which can be used to validate the *JTW*. The validation must be performed by a REST call to the proxy.

.. openapi:: /_static/openapi-spec.yaml
   :paths:
      /auth/contract/validate



OpenAPI Specification
#####################

`Checkout the full OpenAPI spec here <https://editor.swagger.io/?url=https://raw.githubusercontent.com/nuts-foundation/nuts-proxy/init-docs/docs/_static/openapi-spec.yaml>`_
