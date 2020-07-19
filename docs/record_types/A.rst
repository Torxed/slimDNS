A Record
========

| The `A record <https://en.wikipedia.org/wiki/List_of_DNS_record_types#Resource_records>`_ is a general purpose pointer to an IP or CNAME destination.
| Arguably the most common DNS record you'll ever use.

To create such a record, assuming the main server instance is called `dns`, you'd simply do:

.. code-block:: py

    dns.add('hvornum.se', 'A', '192.168.10.1')

This will resolve all DNS request for the host `hvornum.se` to `192.168.10.1`.