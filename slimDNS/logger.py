import logging
from systemd.journal import JournalHandler

log = logging.getLogger('slimDNS')
log.addHandler(JournalHandler(SYSLOG_IDENTIFIER="slimDNS"))
log.setLevel(logging.INFO)