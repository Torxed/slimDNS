# slimDNS

A simple DNS server written in vanilla Python.

# Installation

git clone the repo, and create a `dns_server.py`:

```py
import slimDNS

dns = slimDNS.server(slimDNS.UDP)

dns.run()
```

# Configuration

Place a `records.json` in the working directory of the server root.<br>
Basic syntax boils down to:<br>

```json
{
	"domain.com" : {
		"A" : {"ip" : "260.10.24.12", "type" : "A", "class" : "IN", "ttl" : 60},
		"SOA" : {"ip" : "260.10.24.12", "type" : "SOA", "class" : "IN", "ttl" : 60},
		"NS" : {"ip" : "260.10.24.12", "type" : "NS", "class" : "IN", "ttl" : 60, "priority" : 10, "port" : 8448, "target" : "domain.com"}
	},
	"nas.domain.com" : {
		"A" : {"ip" : "260.10.24.12", "type" : "A", "class" : "IN", "ttl" : 60}
	},
	"_matrix._tcp.riot.domain.com" : {
		"SRV" : {"ip" : "260.10.24.12", "type" : "SRV", "class" : "IN", "ttl" : 60, "priority" : 10, "port" : 8448, "target" : "nas.domain.com"}
	}
}
```

# All in one example

```py
import slimDNS

dns = slimDNS.server(slimDNS.UDP)

@dns.records
def records(server):
	return {
		"example.com" : {
			"A" : {"ip" : "264.30.198.2", "type" : "A", "class" : "IN", "ttl" : 60},
			"SOA" : {"ip" : "264.30.198.2", "type" : "SOA", "class" : "IN", "ttl" : 60},
			"NS" : {"ip" : "264.30.198.2", "type" : "NS", "class" : "IN", "ttl" : 60, "priority" : 10, "port" : 8448, "target" : "example.com"}
		},
		"nas.example.com" : {
			"A" : {"ip" : "264.30.198.2", "type" : "A", "class" : "IN", "ttl" : 60}
		},
		"_matrix._tcp.riot.example.com" : {
			"SRV" : {"ip" : "264.30.198.2", "type" : "SRV", "class" : "IN", "ttl" : 60, "priority" : 10, "port" : 8448, "target" : "nas.example.com"}
		}
	}

dns.run()
```

# Running

    $ sudo python dns_server.py

# Note

Requires Linux, Python 3.8+ and has not been tested outside the lab.