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

.. include:: docs/pages/development/nuts-auth.rst
    :start-after: .. marker-for-readme

Configuration
*************

The following configuration parameters are available:

.. include:: README_options.rst

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
