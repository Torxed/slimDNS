
__version__ = 'v2.0'

import pty
import os
import socket
import select
import json
import traceback
import time
from .argparsing import args
from .helpers import unique_identifier
from .orchistration import Orchestrator
from .session import workers, orchistration

# for identifier in workers:
# 	try:
# 		wait_status = os.waitpid(workers[identifier]['pid'], 0)[1]
# 		exit_code = os.waitstatus_to_exitcode(wait_status)
# 	except ChildProcessError:
# 		exit_code = 1

# 	print(f"{identifier} exited with {exit_code}")