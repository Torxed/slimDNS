slimDNS Documentation
======================

| **slimDNS** is a simple, minimal and flexible DNS server.
| It doesn't require external dependencies and work off Python 3.8 builtins.
| 
| Here's a `demo domain <https://hvornum.se/>`_ using minimal setup: 

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

.. toctree::
   :maxdepth: 3
   :caption: Getting help

   help/discord
   help/issues

.. toctree::
   :maxdepth: 3
   :caption: Record types

   record_types/A
   record_types/NS
   record_types/SOA
   record_types/SRV

.. toctree::
   :maxdepth: 3
   :caption: API Reference

   slimDNS/server
   slimDNS/TCP_SERVER
   slimDNS/UDP_SERVER
   slimDNS/DNS_RESPONSE
   slimDNS/QUERY
   slimDNS/ANSWER
   slimDNS/ADDITIONAL
   slimDNS/Events