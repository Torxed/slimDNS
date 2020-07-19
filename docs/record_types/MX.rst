MX Record
=========

| The `MX record <https://en.wikipedia.org/wiki/List_of_DNS_record_types#Resource_records>`_ is the e-mail record *(Mail Exchange)*.
| This DNS record will let others identify where the primary (and backup) email server is located for e-mail deliveries.

.. note:: This example assuming the main server instance is called `dns`.

.. code-block:: py

    dns.add('hvornum.se', 'MX', 'mail1.hvornum.se', priority=10)
    dns.add('hvornum.se', 'MX', 'mail2.hvornum.se', priority=20)

| This sets up a `MX` record for the domain `hvornum.se`, where the primary mail server server is `mail1.hvornum.se`.
| The second server will be `mail2.hvornum.se`.