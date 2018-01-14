import json, signal
import psycopg2, psycopg2.extras
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from datetime import datetime
from hashlib import sha256
from struct import pack
from time import time, sleep
from os import urandom, getpid
from psycopg2.extras import RealDictRow

from dnslib import DNSLabel, QTYPE, RD, RR, dns
from dnslib import A, AAAA, CNAME, MX, NS, SOA, TXT
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer

from config import config

## https://github.com/samuelcolvin/dnserver/blob/master/dnserver.py

EPOCH = datetime(1970, 1, 1)
SERIAL = int((datetime.utcnow() - EPOCH).total_seconds())

TYPE_LOOKUP = {
	'A': (dns.A, QTYPE.A),
	'AAAA': (dns.AAAA, QTYPE.AAAA),
	'CAA': (dns.CAA, QTYPE.CAA),
	'CNAME': (dns.CNAME, QTYPE.CNAME),
	'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
	'MX': (dns.MX, QTYPE.MX),
	'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
	'NS': (dns.NS, QTYPE.NS),
	'PTR': (dns.PTR, QTYPE.PTR),
	'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
	'SOA': (dns.SOA, QTYPE.SOA),
	'SRV': (dns.SRV, QTYPE.SRV),
	'TXT': (dns.TXT, QTYPE.TXT),
	'SPF': (dns.TXT, QTYPE.TXT),
}

def generate_UID():
	return sha256(pack('f', time()) + urandom(16)).hexdigest()

def wash_dict(d):
	clean = {}
	for key, value in d.items():
		if type(value) in (dict, RealDictRow):
			value = wash_dict(value)
		clean[key] = value
	return clean

def log(*args, **kwargs):
	if config['log']:
		if not 'level' in kwargs or kwargs['level'] >= config['log_level']:
			print('[LOG]',  ' '.join([str(x) for x in args]))

class postgres():
	def __init__(self):
		try:
			self.con = psycopg2.connect("dbname={}} user={} password='{}'".format(config['db']['name'], config['db']['user'], config['db']['password']))
			self.cur = self.con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
		except psycopg2.OperationalError:
			con = psycopg2.connect("dbname=postgres user={} password='{}'".format(config['db']['user'], config['db']['password']))
			con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
			cur = con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
			cur.execute("CREATE DATABASE {};".format(config['db']['name']))
			# con.commit() ## Redundant because we're in a isolated autocommit context.
			cur.close()
			con.close()

			self.con = psycopg2.connect("dbname={}} user={} password='{}'".format(config['db']['name'], config['db']['user'], config['db']['password']))
			self.cur = self.con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

	def __enter__(self):
		self.cur.execute("CREATE TABLE IF NOT EXISTS domains (id BIGSERIAL PRIMARY KEY, \
															  uid VARCHAR(255) NOT NULL, \
															  name VARCHAR(255) NOT NULL, \
															  subnets JSON NOT NULL DEFAULT '{}', \
															  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), \
															  last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), \
															  CONSTRAINT one_domainname UNIQUE (name));")
		self.cur.execute("CREATE INDEX IF NOT EXISTS domain_name ON domains (name);")

		self.cur.execute("CREATE TABLE IF NOT EXISTS records (id BIGSERIAL PRIMARY KEY, \
															  uid VARCHAR(255) NOT NULL, \
															  domain BIGINT NOT NULL, \
															  name VARCHAR(255) NOT NULL, \
															  content VARCHAR(255) NOT NULL, \
															  type VARCHAR(12) NOT NULL DEFAULT 'A', \
															  ttl INT NOT NULL DEFAULT 60, \
															  subnets JSON NOT NULL DEFAULT '{}', \
															  created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), \
															  last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), \
															  CONSTRAINT one_team UNIQUE (domain, name, type, content));")
		self.cur.execute("CREATE INDEX IF NOT EXISTS record_name ON records (name);")

		self.con.commit()
		return self

	def __exit__(self, _type, value, traceback):
		self.close()

	def execute(self, q, commit=True):
		log('SQLExecute: {q} [{commit}]'.format(q=q, commit=commit), level=1)
		self.cur.execute(q)
		if commit:
			log('Commited!', level=1)
			self.con.commit()

			#log(list(self.query('SELECT * FROM access_tokens;')), level=1)

	def query(self, q, commit=False):
		log('SQLQuery: {q} [{commit}]'.format(q=q, commit=commit), level=1)
		self.cur.execute(q)
		if commit:
			self.con.commit()
		if self.cur.rowcount:
			for record in self.cur:
				yield wash_dict(record)

	def close(self, commit=True):
		if commit:
			self.con.commit()
		self.cur.close()
		self.con.close()

class Record:
	def __init__(self, name, record_type, content=None, ttl=None, *args, **kwargs):
		self.name = DNSLabel(name)
		self.raw_qtype = record_type
		if not content: content = name

		rd_cls, self.record_type = TYPE_LOOKUP[record_type]

		if self.record_type == QTYPE.SOA and len(args) == 2:
			# add sensible times to SOA
			args += (SERIAL,  config['soa']['refresh'], config['soa']['retry'], config['soa']['expire'], config['soa']['minimum']),

		if self.record_type == QTYPE.TXT and len(args) == 1 and isinstance(args[0], str) and len(args[0]) > 255:
			# wrap long TXT records as per dnslib's docs.
			args = wrap(args[0], 255),

		if not ttl:
			if self.record_type in (QTYPE.NS, QTYPE.SOA):
				ttl = 60
			else:
				ttl = 60

		self.rr = RR(
			rname=self.name,
			rtype=self.record_type,
			rdata=rd_cls(content),
			ttl=ttl,
		)

	def match(self, q):
		return q.qname == self.name and (q.qtype == QTYPE.ANY or q.qtype == self.record_type)

	def sub_match(self, q):
		pass # For now, not sure what the implications of this is yet.
		#return self.record_type == QTYPE.SOA and q.qname.matchSuffix(self.name)

	def __str__(self):
		return str(self.rr)

class Resolver(ProxyResolver):
	def __init__(self):
		if config['forwarder']:
			super().__init__(config['forwarder'], 53, 5)
		self.zones = {}
		self.last_cacheUpdate = time()
		self.update_cache()
		for zone, records in self.zones.items():
			log('[Zone] Loaded {} with {} records.'.format(zone, len(records)))

	def update_cache(self):
		with postgres() as db:
			for domain_row in list(db.query("SELECT * FROM domains;")):
				records = []
				for record in db.query("SELECT * FROM records WHERE domain={}".format(domain_row['id'])):
					if record['type'] in TYPE_LOOKUP:
						records.append(Record(record_type=record['type'], domain=domain_row['name'], name=record['name'], content=record['content'], ttl=record['ttl']))
				self.zones[DNSLabel(domain_row['name'])] = records

	def traverse_records(self, zone, request, reply, traverse=False):
		if not zone: return reply

		for record in zone:
			if record.match(request.q):
				reply.add_answer(record.rr)
			elif traverse and record.sub_match(request.q):
				reply.add_answer(record.rr)

	def resolve(self, request, handler):
		if time() - self.last_cacheUpdate > 30:
			self.update_cache()

		reply = request.reply()
		self.traverse_records(self.zones.get(request.q.qname), request, reply)

		if not reply.rr:
			## No results found,
			## try updating the cache.
			self.update_cache()
			self.traverse_records(self.zones.get(request.q.qname), request, reply)

			if not reply.rr:
				# Still no results,
				# look for a SOA record for a higher level zone
				self.traverse_records(self.zones.get(request.q.qname), request, reply, traverse=True)

		if config['forwarder'] and not reply.rr:
			return super().resolve(request, handler)

		return reply

def signal_handler(signum, frame):
	log('pid={}, got signal: {}, stopping...'.format(getpid(), signal.Signals(signum).name))
	exit(0)
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

resolver = Resolver()
servers = [
	DNSServer(resolver, port=5053, address='localhost', tcp=True),
	DNSServer(resolver, port=5053, address='localhost', tcp=False),
]

if __name__ == '__main__':
	for s in servers:
		s.start_thread()

	try:
		while 1:
			sleep(0.1)
	except KeyboardInterrupt:
		pass
	finally:
		for s in servers:
			s.stop()