SOA Record
==========

| The `SOA record <https://en.wikipedia.org/wiki/List_of_DNS_record_types#Resource_records>`_ is the `Start of Authority` record.
| This contains all the main information top DNS servers need to identify your DNS server as a authority for the asked domain.

.. note:: This example assuming the main server instance is called `dns`.

.. code-block:: py

    dns.add('hvornum.se', 'SOA', email='root@hvornum.se', target='ns1.hvornum.se')

| This sets up a `SOA` record for the domain `hvornum.se`, where the primary DNS server (`target´) is `ns1.hvornum.se`.
| And the contact e-mail for the domain is `root@hvornum.se`.