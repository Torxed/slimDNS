config = {
	'soa' : {'refresh' : 60,
			'retry' : 60,
			'expire' : 60,
			'minimum' : 60},
	'forwarder' : None,
	'log_level' : 2,
	'log' : True,

	'recursive' : ['MX'], # or 'recursive' : None, - if you wanna unallow it

	'db' : {'name' : 'slimdns',
			'user' : 'slimdns',
			'password' : 'Extremely long, random password (Usage of it later is optional if you\'re on localhost.)'}
}
