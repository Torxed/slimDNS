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