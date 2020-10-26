.. _nuts-auth-development:

Nuts auth development
#####################

.. marker-for-readme

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

Generate the api package from the OpenAPI specification

.. code-block:: shell

    oapi-codegen -generate server,types -package api docs/_static/nuts-auth.yaml > api/generated.go

Embed files like certificates from the bindata directory

.. code-block:: shell

    go-bindata -ignore=\\.DS_Store -pkg=assets -o=./assets/bindata.go -prefix=bindata ./bindata/...

Generating Mock
***************

When making changes to the client interface run the following command to regenerate the mock:

.. code-block:: shell

    mockgen -destination=mock/mock_auth_client.go -package=mock -source=pkg/auth.go
    mockgen -destination=mock/services/mock.go -package=services -source=pkg/services/services.go


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
