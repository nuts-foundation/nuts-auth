.. image:: https://travis-ci.com/nuts-foundation/nuts-auth.svg?branch=master
    :target: https://travis-ci.com/nuts-foundation/nuts-auth
    :alt: Test status

.. image:: https://codecov.io/gh/nuts-foundation/nuts-proxy/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/nuts-foundation/nuts-auth
    :alt: Test coverage

.. image:: https://godoc.org/github.com/nuts-foundation/nuts-auth?status.svg
    :target: https://godoc.org/github.com/nuts-foundation/nuts-auth
    :alt: GoDoc

.. image:: https://api.codacy.com/project/badge/Grade/e1c0eca9935049d590ab78f8c808cfa0
    :target: https://www.codacy.com/app/nuts-foundation/nuts-auth?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=nuts-foundation/nuts-auth&amp;utm_campaign=Badge_Grade
    :alt: Codacy Report

Nuts Auth Service
==================


Start the server with ``go run main.go serve -p 3000``

Copy the ``testfonfig.yaml`` from the testdata directory and change its values.

Start the server with ``go run main.go serve --config-file config --config-file-path .``

For more information about how to use the server type ``go run main.go``

Documentation
=============
The spec of this service is provided in the ``docs`` folder. The latest version is hosted on `Read the docs <https://nuts-service-proxy.readthedocs.io/en/latest/`_.


Development
===========

A skaffold file is provided in k8s. Install a local kubernetes cluster and run ``skaffold dev -f k8s/skaffold.yaml``
to build, test and run the docker image.

For testing the docker binary you need to install https://github.com/GoogleContainerTools/container-structure-test .

If you do not want to test the docker image, include ``--skip-tests``.
