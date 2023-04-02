import argparse
import pathlib

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

args, unknown = main_options.parse_known_args()