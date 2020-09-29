=========================  ==============  =========================================================================================================================
Key                        Default         Description                                                                                                              
=========================  ==============  =========================================================================================================================
actingPartyCn                              The acting party Common name used in contracts                                                                           
address                    localhost:1323  Interface and port for http server to bind to, default: localhost:1323                                                   
enableCORS                 false           Set if you want to allow CORS requests. This is useful when you want browsers to directly communicate with the nuts node.
irmaConfigPath                             path to IRMA config folder. If not set, a tmp folder is created.                                                         
irmaSchemeManager          pbdf            The IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo', default: pbdf                         
mode                                       server or client, when client it does not start any services so that CLI commands can be used.                           
oAuthKeyGeneration         true            Auto generate OAuth JWT signing key if missing.                                                                          
oAuthSigningKey                            Path to PEM encoded private key.                                                                                         
publicUrl                                  Public URL which can be reached by a users IRMA client                                                                   
skipAutoUpdateIrmaSchemas  false           set if you want to skip the auto download of the irma schemas every 60 minutes.                                          
=========================  ==============  =========================================================================================================================
