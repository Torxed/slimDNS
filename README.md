# slimDNS

A simple DNS server written in vanilla Python.

# Setup:

a `records.json` in the working directory.<br>
Basic syntax boils down to:<br>

```json
{
	"domain.com" : {
		"A" : {"ip" : "127.0.0.1", "type" : "A", "class" : "IN", "ttl" : 60},
		"SOA" : {}
	}
}
```

# Running

    $ sudo python slimDNS.py

# Note

Requires Linux, Python 3.3+ and has not been tested outside the lab.