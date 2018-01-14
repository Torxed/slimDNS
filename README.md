# slimDNS
A simple DNS server (that requires [python-dnslib](https://github.com/andreif/dnslib) unfortunately)

# Setup:

Create a user/role called "slimdns"

    [postgres@machine~] createuser --interactive
    [postgres@machine~] psql
    > CREATE DATABASE slimdns OWNER slimdns;
    > ALTER USER slimdns WITH PASSWORD '<some secure random string>';

# Running:

    [postgres@machine~] python slimdns.py

# Handy information

 * Updates cache every 30 seconds.
 * Does support a forwarding DNS server
 * (Will try to create database slimdns if doesn't excist, but will then need permissions to create databases)
 * Might crash for no aparent reason :D