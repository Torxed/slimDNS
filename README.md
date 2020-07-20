# slimDNS

A simple DNS server written in vanilla Python.

 * slimDNS [documentation](https://slimdns.readthedocs.io/en/latest/)
 * slimDNS [discord](https://discord.gg/CMjZbwR) server
 * slimDNS supports [A](https://slimdns.readthedocs.io/en/latest/record_types/A.html), [NS](https://slimdns.readthedocs.io/en/latest/record_types/NS.html), [SOA](https://slimdns.readthedocs.io/en/latest/record_types/SOA.html) and [SRV](https://slimdns.readthedocs.io/en/latest/record_types/SRV.html) records *(as of v1.0.0rc2)*.

# Installation

    pip install slimDNS

or simply `git clone` this repository.

## Minimal example

```py
import slimDNS

dns = slimDNS.server(slimDNS.UDP)

dns.run()
```

This would host a DNS server without any records.<br>
There's two ways you can add records:

Swap out all records via annotation
-----------------------------------
```py
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
```

Which would swap out all current records for the defined set of records.

Add, delete and update records
------------------------------

```py
dns.remove('example.com', 'A')
dns.add('example.com', 'A', '264.30.198.1')
dns.update('example.com', 'A', '264.30.198.5')
```

Which would remove the `A` record `example.com`,<br>
Then add a *new* similar one with a new `IP`.<br>
Finally, update that new record with a new `IP`.

# Note

Requires Python 3.8+ & ~Linux~ *(not tested on other platforms)*.
