slimDNS Documentation
======================

| **slimDNS** is a simple, minimal and flexible DNS server.
| It doesn't require external dependencies and work off Python 3.8 builtins.
| 
| Here's a `demo <https://hvornum.se/>`_ using minimal setup: 

.. code-block:: py

    import slimDNS

    dns = slimDNS.server(slimDNS.UDP)

    dns.run()
    @dns.records
    def records(server):
        return {
            "hvornum.se" : {
                  "A" : {"target" : "46.21.102.81", "ttl" : 60},
                  "SOA" : {"target" : "hvornum.se", "ttl" : 60},
                  "NS" : {"target" : "hvornum.se", "ttl" : 60, "priority" : 10}
            }
        }

Some of the features of slimDNS are:

* **No external dependencies or installation requirements.** Runs without any external requirements or installation processes.

* **Single threaded.** slimDNS takes advantage of `select.epoll()` *(select.select() on Windows)* to achieve blazing speeds without threading the service. Threads are allowed and welcome, but the core code relies on using as few threads and overhead as possible.

.. toctree::
   :maxdepth: 3
   :caption: Programming Guide

   programming_guide/installation
   programming_guide/configuration
   programming_guide/websockets

.. toctree::
   :maxdepth: 3
   :caption: Examples

   examples/basic

.. toctree::
   :maxdepth: 3
   :caption: Getting help

   help/discord
   help/issues

.. toctree::
   :maxdepth: 3
   :caption: API Reference

   slimDNS/host
   slimDNS/HTTP_SERVER
   slimDNS/HTTPS_SERVER
   slimDNS/HTTP_REQUEST
   slimDNS/HTTP_RESPONSE
   slimDNS/ROUTE_HANDLER
   slimDNS/HTTP_CLIENT_IDENTITY
   slimDNS/Events

.. toctree::
   :maxdepth: 3
   :caption: Internal Functions

   slimDNS/handle_py_request
   slimDNS/get_file
   slimDNS/CertManager
   slimDNS/slimDNS_Error
   slimDNS/ConfError
   slimDNS/NotYetImplemented
   slimDNS/UpgradeIssue