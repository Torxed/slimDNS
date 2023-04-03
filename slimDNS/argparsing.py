import argparse
import pathlib
import ipaddress
from .types import Interface

# Parse script arguments and use defaults from configuration where needed
main_options = argparse.ArgumentParser(description="A minemalistic DNS with true multi-threading written in vanilla Python.", add_help=True)
main_options.add_argument(
	"--workers",
	type=int,
	default=2,
	nargs="?",
	help="Dictates how many multi-threading workers to spawn"
)
main_options.add_argument(
	"--thread-socket",
	type=pathlib.Path,
	default=pathlib.Path('/tmp/slimDNS.socket'),
	nargs="?",
	help="Sets the UNIX socket where the threads communicate over"
)
main_options.add_argument(
	"--interface",
	type=Interface('lo'),
	default=Interface('lo'),
	nargs="?",
	help="Defines which interface to bind the DNS queries to"
)
main_options.add_argument(
	"--framesize",
	type=int,
	default=1500,
	nargs="?",
	help="Defines the TCP/UDP framesize to use per package sent over the wire"
)
main_options.add_argument(
	"--port",
	type=int,
	default=53,
	nargs="?",
	help="Defines the TCP/UDP port to listen to for DNS requests"
)
main_options.add_argument(
	"--address",
	type=ipaddress.ip_address,
	default='',
	nargs="?",
	help="Dictates which address we should monitor for DNS requests on (default all IPs)"
)

args, unknown = main_options.parse_known_args()