#!/usr/bin/python26
"""
Author: ml623@georgetown.edu
Adpapted from:
https://github.com/mediawiki/mediawiki-svn/blob/trunk/tools/selective-answer/selective-answer.py
Added: Monitoring remote http servers asyncronisouly, using gevent.
"""
import gevent
from gevent import monkey, Greenlet
# patches stdlib (including socket and ssl modules) to cooperate with other greenlets
monkey.patch_all()

import sys, fcntl, os
import logging
import logging.handlers
logger = logging.getLogger()
formatter = logging.Formatter('%s(%d): %%(levelname)s: %%(message)s'%(os.path.basename(sys.argv[0]),os.getpid()))
logger.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address='/dev/log')
handler.setFormatter(formatter)
logger.addHandler(handler)


from pglb.records import Records
from pglb.processor import Processor
        


def system_hacks():
    # make stdin a non-blocking file
    fd = sys.stdin.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    
    # We appear to end up with superfluous FDs, including pipes from other
    # instances, forked from PowerDNS. This can keep us and others from
    # exiting as the fd never gets closed. Close all fds we don't need.
    try:
        import resource
        maxfds = resource.getrlimit(resource.RLIMIT_NOFILE)[1] + 1
        # OS-X reports 9223372036854775808. That's a lot of fds to close
        if maxfds > 1024:
            maxfds = 1024
    except:
        maxfds = 256

    
if __name__=="__main__":
    
    system_hacks()
    
    records = Records(config_filename = "/etc/pdns/pdns_pipe.conf",interval=10)
    processor = Processor(records.data,pdns_timeout=60)
    records.processor = processor
    records.start()
    processor.start()
    
    gevent.joinall([records,processor])
    

