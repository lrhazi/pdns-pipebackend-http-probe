from gevent import sleep, Greenlet
from gevent.socket import wait_read, timeout
import sys, time
import logging
logger = logging.getLogger()

class Processor(Greenlet):
    
    def __init__(self,dns_records,pdns_timeout=60):
        Greenlet.__init__(self)
        self.dns_records = dns_records
        self.pdns_timeout = pdns_timeout
        self.time = None

    def _run(self):
        while True:
            line = None
            try:
                wait_read(sys.stdin.fileno(),timeout=self.pdns_timeout)
            except timeout:
                logger.info('Timed out wating for input from PowerDNS. Exiting...')
                break
            self.time = time.time()
            line = sys.stdin.readline().strip()
            if line:
                #logger.debug('received: %s'%line)
                self.processLine(line)
            else:
                logger.info('received empty line from PowerDNS. Exiting...')
                break
            sys.stdout.flush()

    def processLine(self,line):
        line = line.strip()
        words = line.split('\t')
        #logger.debug('parsing tokens: %s'%words)
        try:
            if words[0] == "HELO":
                if words[1] != "2":
                    print "LOG\tUnknown version", words[1]
                    print "FAIL"
                else:
                    print "OK\tGU Dynamic DNS Resolution Backend."
                    logger.info('received HELO from PowerDNS')
            elif words[0] == "Q":
                self.query(words[1:7])
            elif words[0] == "AXFR":
                self.axfr(words[1])
            elif words[0] == "PING":
                pass    # PowerDNS doesn't seem to do anything with this
            else:
                raise IndexError
        except IndexError, ValueError:
            print "LOG\tPowerDNS sent an unparseable line: '%s'" % line
            print "FAIL"    # FAIL!

    def answerRecord(self, qNameSet, (qName, qClass, qType, qId, remoteIp, localIp)):
        qNameSet, qNameSet_lastresort = qNameSet
        done = False
        for record in qNameSet:
            rQType, ttl, content, lb_method, monitor = record
            if monitor.up and qType in (rQType, 'ANY', 'AXFR'):
                done = True
                answer = "DATA\t%s\t%s\t%s\t%d\t%d\t%s" % (qName, 'IN', rQType, ttl, int(qId), content)
                #logger.debug('answerRecord: Printing answer: %s'%answer)
                print answer
        if not done:
            for record in qNameSet_lastresort:
                rQType, ttl, content = record
                if qType in (rQType, 'ANY', 'AXFR'):
                    answer = "DATA\t%s\t%s\t%s\t%d\t%d\t%s" % (qName, 'IN', rQType, ttl, int(qId), content)
                    #logger.debug('answerRecord: Printing answer: %s'%answer)
                    print answer
                    
    
    def query(self, (qName, qClass, qType, qId, remoteIp, localIp)):
        #logger.debug('parsing query: %s %s %s %s %s %s'%(qName, qClass, qType, qId, remoteIp, localIp))
        if qClass == 'IN' and qName.lower() in self.dns_records:
            self.answerRecord(self.dns_records[qName.lower()], (qName, qClass, qType, qId, remoteIp, localIp))
        print "END"
    
    def axfr(self, id):
        for qName, qNameSet in self.dns_records.iteritems():
            answerRecord(qNameSet, (qName, "IN", "AXFR", id, "None", "None"), set())
        print "END"

    def __str__(self):
        return 'processInput Greenlet'
