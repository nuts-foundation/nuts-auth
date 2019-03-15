Auth Module
===========

The Authentication module enables the :doc:`Vendor space <nuts-documentation:pages/architecture>` to perform operations related to authentication.
We use authentication contracts in which a user gives consent to an acting party to operate on data on its behalves.
See contracts in the main documentation :doc:`nuts-documentation:pages/login-contract`

In a cross Nuts node operation we have two roles, one for each party:
The **acting party**, the one who serves its user and makes the request.
The **serving party**, the one who serves the data of the patient and reveives the request.


Create auth contract for user
#############################

In order for a user to operate on data stored in another system, the software serving the user should craft a special token which proves that the acting party is authorized to perform a query on behalve of its user.

The Nuts proxy provides a convenient endpoint which can be used to initiate the authentication process. The acting party chooses the type of contract and the language.
The system creates a session and returns an URL with the session information. The acting party should present this endpoint to its user who can choose to interact with this endpoint and sign the consent.

Since the interaction between the user and IRMA are out of bound, the acting party does not know when the transaction is completed. Therefor it needs to poll or subscribe to changes in the transaction status.

When the transaction between the user and IRMA completes, the acting party receives the fully signed contract which it can use to make requests to other Nuts parties.

.. figure:: /_static/images/irma-login.sequence-diagram.png
    :width: 600px
    :align: center
    :alt: Irma consent login sequence diagram
    :figclass: align-center

.. openapi:: /_static/openapi-spec.yaml
   :paths:
      /auth/contract/{type}
      /auth/contract




Validate auth contract from user
################################

When the EHR system receives a request on its APIs from another Nuts party, it needs ti vakudate the validity of the authorization token.

The Nuts proxy provides a convenient endpoint which can be used to validate the token. The validation must be performed by a single REST call to the proxy.

.. openapi:: /_static/openapi-spec.yaml
   :paths:
      /auth/contract/validate

