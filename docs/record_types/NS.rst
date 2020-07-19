NS Record
=========

| The `NS record <https://en.wikipedia.org/wiki/List_of_DNS_record_types#Resource_records>`_ is the Name Server record.
| This points clients and servers towards a DNS server for a particular domain/name/record.

.. note:: This example assuming the main server instance is called `dns`.

.. code-block:: py

    dns.add('hvornum.se', 'NS', 'ns1.hvornum.se')

This creates a record that tells anyone asking, that the primary name server for `hvornum.se` is located at `ns1.hvornum.se`.

.. note:: There are other options as well, such as `ttl=3600`. But a basic record can be created with only these three options.