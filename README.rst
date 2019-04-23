
.. image:: https://readthedocs.org/projects/nuts-service-proxy/badge/?version=latest
    :target: https://nuts-documentation.readthedocs.io/projects/nuts-service-proxy/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://travis-ci.com/nuts-foundation/nuts-proxy.svg?branch=master
    :target: https://travis-ci.com/nuts-foundation/nuts-proxy
    :alt: Test status


Nuts Service Proxy
==================


Start the server with ``go run main.go serve -p 3000``

Copy the ``testfonfig.yaml`` from the testdata directory and change its values.
Start the server with ``go run main.go serve --config-file config --config-file-path .``
For more information about how to use the server type ``go run main.go``


Development
===========

A skaffold file is provided in k8s. Install a local kubernetes cluster and run ``skaffold dev -f k8s/skaffold.yaml``
to build, test and run the docker image.
For testing the docker binary you need to install https://github.com/GoogleContainerTools/container-structure-test .
If you do not want to test the docker image, include ``--skip-tests``.
