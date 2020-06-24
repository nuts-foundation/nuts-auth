Nuts Auth Service
##################

.. image:: https://circleci.com/gh/nuts-foundation/nuts-auth.svg?style=svg
    :target: https://circleci.com/gh/nuts-foundation/nuts-auth
    :alt: Build Status

.. image:: https://codecov.io/gh/nuts-foundation/nuts-proxy/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/nuts-foundation/nuts-auth
    :alt: Test coverage

.. image:: https://godoc.org/github.com/nuts-foundation/nuts-auth?status.svg
    :target: https://godoc.org/github.com/nuts-foundation/nuts-auth
    :alt: GoDoc

.. image:: https://api.codeclimate.com/v1/badges/a96e5a12e2fcc618a525/maintainability
   :target: https://codeclimate.com/github/nuts-foundation/nuts-auth/maintainability
   :alt: Maintainability

The auth module is written in Go and should be part of nuts-go as an engine.

Dependencies
************

This projects is using go modules, so version > 1.12 is recommended. 1.10 would be a minimum.

Running tests
*************

Tests can be run by executing

.. code-block:: shell

    go test ./...

Generating code
***************

.. code-block:: shell

    oapi-codegen -generate server,types -package api docs/_static/nuts-auth.yaml > api/generated.go

Generating Mock
***************

When making changes to the client interface run the following command to regenerate the mock:

.. code-block:: shell

    mockgen -destination=mock/mock_client.go -package=mock -source=pkg/auth.go


Building
********

This project is part of https://github.com/nuts-foundation/nuts-go. If you do however would like a binary, just use ``go build``.

README
******

The readme is auto-generated from a template and uses the documentation to fill in the blanks.

.. code-block:: shell

    ./generate_readme.sh

This script uses ``rst_include`` which is installed as part of the dependencies for generating the documentation.

Documentation
*************

To generate the documentation, you'll need python3, sphinx and a bunch of other stuff. See :ref:`nuts-documentation-development-documentation`
The documentation can be build by running

.. code-block:: shell

    /docs $ make html

The resulting html will be available from ``docs/_build/html/index.html``

Configuration
*************

The following configuration parameters are available for the auth service.

===================================     ======================================  ========================================
Key                                     Default                                 Description
===================================     ======================================  ========================================
auth.mode                               server                                  server or client. nuts-auth doesn't support true client mode (yet), but when specified it doesn't start any services (like IRMA) so that CLI commands can be used.
auth.publicUrl                          ""                                      Public URL which can be reached by a users IRMA client
auth.irmaConfigPath                     ""                                      path to IRMA config folder. If not set, a tmp folder is created
auth.actingPartyCn                      ""                                      The acting party Common name used in contracts
auth.skipAutoUpdateIrmaSchemas          false                                   set if you want to skip the auto download of the irma schemas every 60 minutes
auth.enableCORS                         false                                   Set if you want to allow CORS requests. This is useful when you want browsers to directly communicate with the nuts node
auth.irmaSchemeManager                  pbdf                                    Allows selecting an IRMA scheme manager. During development this can ben irma-demo. Should be pdfb in strictMode
===================================     ======================================  ========================================

As with all other properties for nuts-go, they can be set through yaml:

.. sourcecode:: yaml

    auth:
       publicUrl: "https://nuts.nl"

as commandline property

.. sourcecode:: shell

    ./nuts --auth.publicUrl https://nuts.nl

Or by using environment variables

.. sourcecode:: shell

    NUTS_AUTH_PUBLIC_URL=https://nuts.nl ./nuts

