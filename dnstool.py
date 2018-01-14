import sys
import psycopg2, psycopg2.extras
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from hashlib import sha256
from struct import pack
from time import time
from os import urandom
from psycopg2.extras import RealDictRow

from config import config

def generate_UID():
	return sha256(pack('f', time()) + urandom(16)).hexdigest()

def wash_dict(d):
	clean = {}
	for key, value in d.items():
		if type(value) in (dict, RealDictRow):
			value = wash_dict(value)
		clean[key] = value
	return clean

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
		self.cur.execute(q)
		if commit:
			self.con.commit()

	def query(self, q, commit=False):
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

def get_domainID(UID):
	with postgres() as db:
		for row in db.query("SELECT id FROM domains WHERE uid='{UID}' or name='{UID}';".format(UID=UID)):
			return row['id']

def get_domainUID(did):
	with postgres() as db:
		for row in db.query("SELECT uid FROM domains WHERE name='{id}' OR id={id};".format(id=did)):
			return row['uid']

def get_recordUID(domain, name, record_type):
	with postgres() as db:
		for row in db.query("SELECT uid FROM records WHERE domain={} AND name='{}' AND type='{}';".format(domain, name, record_type)):
			return row['uid']

def add_domain(dname, add_default_records=False):
	UID = generate_UID()
	with postgres() as db:
		for row in db.query("SELECT uid FROM domains WHERE name='{}';".format(dname)):
			return row['uid']
		db.execute("INSERT INTO domains (uid, name) VALUES ('{}', '{}');".format(UID, dname))
		if add_default_records:
			add_record(dname, dname, dname, 'SOA')
			add_record(dname, dname, dname, 'NS')
	return UID

def add_record(domain, name, content, record_type='A', ttl=60):
	if record_type is None: record_type = 'A'
	if ttl is None: ttl = 60
	if type(domain) != int or domain.isnumeric() == False: domain = get_domainID(domain)

	UID = generate_UID()
	with postgres() as db:
		try:
			db.execute("INSERT INTO records (uid, domain, name, content, type, ttl) VALUES ('{}', {}, '{}', '{}', '{}', {});".format(UID, domain, name, content, record_type, ttl))
		except psycopg2.IntegrityError:
			return get_recordUID(domain, name, record_type)

	return UID

fname, sys.argv = sys.argv[0], sys.argv[1:]
if len(sys.argv) < 1:
	print('Usage:'\
		  '$ python dnstool.py hvornum.se'\
		  '	- Adds a domain and a SOA record. (optional)'\
		  '$ python dnstool.py hvornum.se 46.21.102.81'\
		  '	- This adds the above but also a A record pointing to the IP.'\
		  '$ python dnstool.py hvornum.se 46.21.102.81 A'\
		  ' - All the above, but specifies the record type'\
		  '$ python dnstool.py mail.hvornum.se "46.21.102.81 10" MX'\
		  ' - All above, but this is how you add type-specific options.')

elif len(sys.argv) == 1:
	print('Domain UID: {}'.format(add_domain(sys.argv[0])))

elif len(sys.argv) > 1:
	record, content = sys.argv[:2]
	record_type, ttl = None, None
	if len(sys.argv) == 4:
		record_type = sys.argv[4]
	if len(sys.argv) == 5:
		ttl = sys.argv[5]
	
	domain = record[record.find('.')+1:] if record.count('.') > 1 else record
	print()
	domain_uid = add_domain(domain, add_default_records=True)
	print('Domain UID: {}'.format(domain_uid))
	print('Record UID: {}'.format(add_record(domain, record, content, record_type, ttl)))