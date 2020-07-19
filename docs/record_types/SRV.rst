SRV Record
==========

| The `SRV record <https://en.wikipedia.org/wiki/List_of_DNS_record_types#Resource_records>`_ is a service locator record.
| This helps others identify certain services such as Active Directory, chat servers etc.

.. note:: This example assuming the main server instance is called `dns`.

.. code-block:: py

    dns.add('_chat._tcp.hvornum.se', 'SRV', target='chat.hvornum.se', port=8080, priority=10)

| This creates a `SRV` record that tells a chat application, that the primary host and port for the chat is located at `tcp://chat.hvornum.se:8080`.