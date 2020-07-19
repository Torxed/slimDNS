.. _configuration:

*************
Configuration
*************

| Configuration is done by supplying slimDNS with a `dict` of records.
| A complete example can be found under `Baisc setup config`_.
| But as a small example, this would run a DNS server:

.. warning::
    | There's two startup-sensitive configuration options.
    | Those are `addr` and `port` to set the listening interface other than default `0.0.0.0:53`.

    To delcare `addr` and `port` - you have to do it from the startup code:

    .. code-block:: py

        import slimDNS
        
        http = slimDNS.server(slimDNS.UDP, addr='127.0.0.1', port=8080)
        http.run()

    Trying to set it in the runtime configuration will fail, as the server has already setup the `socket.bind((addr, port))`

.. note::
    | Also note that record definitions are done by the developers code that imported slimDNS.
    | It's there for up to the developer if the records should be stored on disk in a particular format or in the code itself.

.. note::
    | All records can be changed in runtime without needing to reload the server.
    | The records can be modified in four different ways:

Baisc setup config
==================

.. code-block:: py

    import slimDNS

    dns = slimDNS.server(slimDNS.UDP)

    @dns.records
    def records(server):
        return {
            "example.com" : {
                "A" : {"target" : "264.30.198.2", "ttl" : 60},
                "SOA" : {"target" : "example.com", "ttl" : 60},
                "NS" : {"target" : "example.com", "ttl" : 60, "priority" : 10}
            },
            "nas.example.com" : {
                "A" : {"target" : "264.30.198.2", "type" : "A", "ttl" : 60}
            },
            "_matrix._tcp.riot.example.com" : {
                "SRV" : {"ttl" : 60, "priority" : 10, "port" : 8448, "target" : "nas.example.com"}
            }
        }

    dns.run()

| Here, records are loaded after the server has started up.
| All the records become active immediately weither or not they are valid/correct.

.. warning::

    | The annotation `@dns.records` replaces any previous records.
    | This is there for only useful if you want to purge previous records and update with a new set.

Adding records
==============

| Records can be added one by one without replacing the previous ones with :func:`~slimDNS.TCP_SERVER.add()`.

.. code-block:: py

    import slimDNS

    dns = slimDNS.server(slimDNS.UDP)

    dns.add('example.com', 'A', '264.30.198.1')

    dns.run()

Removing records
================

| Records can be deleted one by one without affecting other records via the :func:`~slimDNS.TCP_SERVER.remove()`.

.. code-block:: py

    import slimDNS

    dns = slimDNS.server(slimDNS.UDP)

    dns.remove('example.com', 'A')

    dns.run()

Updating records
================

| Records can also be updated individually :func:`~slimDNS.TCP_SERVER.update()`.

.. code-block:: py

    import slimDNS

    dns = slimDNS.server(slimDNS.UDP)

    dns.update('example.com', 'A', '264.30.198.5')

    dns.run()