
.. image:: https://readthedocs.org/projects/nuts-service-proxy/badge/?version=latest
    :target: https://nuts-documentation.readthedocs.io/projects/nuts-service-proxy/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://travis-ci.com/nuts-foundation/nuts-proxy.svg?branch=master
    :target: https://travis-ci.com/nuts-foundation/nuts-proxy
    :alt: Test status

.. image:: https://codecov.io/gh/nuts-foundation/nuts-proxy/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/nuts-foundation/nuts-proxy
    :alt: Test coverage


Nuts Service Proxy
==================


Start the server with ``go run main.go serve -p 3000``

Copy the ``testfonfig.yaml`` from the testdata directory and change its values.

Start the server with ``go run main.go serve --config-file config --config-file-path .``

For more information about how to use the server type ``go run main.go``

Documentation
=============
The spec of this service is provided in the ``docs`` folder. The latest version is hosted on `<https://nuts-service-proxy.readthedocs.io/en/latest/`_.

To build it yourself:

You first have to install python, check `<https://www.python.org/>`_ on how to install python for your OS.
Next you have to install `pip <https://pip.pypa.io/en/stable/installing/>`_.
Then install the following components using **pip**::

    pip install sphinx --user
    pip install recommonmark
    pip install sphinx_rtd_theme
    pip install sphinxcontrib.httpdomain

For MacOS make sure the sphinx executables are added to your PATH::

    export PATH=$HOME/Library/Python/2.7/bin:$PATH

Then you can generate the documentation locally with::

    make html

For small changes you might want to add the *clean* directive::

    make clean html

The documentation will then be available from ``_build/html/index.html``



Development
===========

A skaffold file is provided in k8s. Install a local kubernetes cluster and run ``skaffold dev -f k8s/skaffold.yaml``
to build, test and run the docker image.

For testing the docker binary you need to install https://github.com/GoogleContainerTools/container-structure-test .

If you do not want to test the docker image, include ``--skip-tests``.
