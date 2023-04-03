import slimDNS

orchistration = slimDNS.Orchestrator()

while len(slimDNS.workers) <= slimDNS.args.workers:
	spawn_identifier = slimDNS.unique_identifier()
	slimDNS.workers[spawn_identifier] = {'pid' : orchistration.spawn(spawn_identifier), 'socket' : None, 'identifier' : spawn_identifier, 'alive' : False}

try:
	orchistration.run()
except KeyboardInterrupt:
	for identifier in slimDNS.workers:
		orchistration.send(identifier, {"ACTION": "CLOSE", "IDENTIFIER": identifier})