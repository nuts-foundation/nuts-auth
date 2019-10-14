.. _nuts-auth-configuration:

Nuts auth configuration
#######################

.. marker-for-readme

The following configuration parameters are available for the auth service.

===================================     ======================================  ========================================
Key                                     Default                                 Description
===================================     ======================================  ========================================
auth.publicUrl                          ""                                      Public URL which can be reached by a users IRMA client
auth.mode                               server                                  server or client, when client it uses the HttpClient
auth.irmaConfigPath                     ""                                      path to IRMA config folder. If not set, a tmp folder is created
auth.actingPartyCn                      ""                                      The acting party Common name used in contracts
auth.skipautoUpdateIrmaSchemas          false                                   set if you want to skip the auto download of the irma schemas every 60 minutes
auth.enableCORS                         false                                   Set if you want to allow CORS requests. This is useful when you want browsers to directly communicate with the nuts node
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