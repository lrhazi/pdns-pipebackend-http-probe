#!/usr/bin/python26
"""
Author: ml623@georgetown.edu
Adpapted from:
https://github.com/mediawiki/mediawiki-svn/blob/trunk/tools/selective-answer/selective-answer.py
Added: Monitoring remote http servers asyncronisouly, using gevent.
"""
import gevent
from gevent import monkey, sleep, Timeout, Greenlet
from gevent.socket import wait_read
# patches stdlib (including socket and ssl modules) to cooperate with other greenlets
monkey.patch_all()
import sys, fcntl, os, time
import urllib2
import syslog

class UpdateRecords(Greenlet):
    
    def __init__(self,data,sleep_time=1,probe_interval=10,probe_timeout=5):
        Greenlet.__init__(self)
        self.processor=None
        self.sleep_time = sleep_time
        self.probe_timeout = probe_timeout
        self.probe_interval = probe_interval
        self.probe_time = time.time() - self.probe_interval
        self.vips = data['vips']
        self.records = data['records']
        self.records_lastresort = data['records_lastresort']
        self.names = data['names']
        self.dns_records = {}
        for n in self.names:
            self.dns_records[n] = self.records

    def _run(self):
        while True:
            if self.processor.dead:
                break
            if time.time() - self.probe_time > self.probe_interval:
                self.work()
                self.probe_time=time.time()
            sleep(self.sleep_time)

    def work(self):
        self.records = []
        for vip in self.vips:
            if self.probeVIP(vip,timeout=self.probe_timeout):
                self.records.append(('A', 300, vip))
    
        if not len(self.records):
            self.records = self.records_lastresort
    
        for n in self.names:
            self.dns_records[n] = self.records
        
    def probeVIP(self,ip,protocol='http',uri="/",port=80,timeout=10):
        url = '%s://%s:%d%s' % (protocol,ip,port,uri)
        ok=False
        try:
            r=urllib2.urlopen(url,None,timeout)
            ok = True
        except urllib2.URLError,e:
            pass
        except urllib2.HTTPError,e:
            pass
        finally:
            syslog.syslog('probeVIP: %s Result: %s'%(url,ok))
            return ok
            
    def __str__(self):
        return 'UpdateRecords Greenlet'
        

class ProcessInput(Greenlet):
    
    def __init__(self,dns_records):
        Greenlet.__init__(self)
        self.dns_records = dns_records
        syslog.syslog('ProcessInput init.  dns_records: %s'%self.dns_records)

    def _run(self):
        while True:
            line = None
            wait_read(sys.stdin.fileno())
            line = sys.stdin.readline().strip()
            if line:
                syslog.syslog('received: %s'%line)
                self.processLine(line)
            else:
                syslog.syslog('received empty line from PowerDNS. Exiting')
                break
            sys.stdout.flush()

    def processLine(self,line):
        line = line.strip()
        words = line.split('\t')
        syslog.syslog('parsing tokens: %s'%words)
        try:
            if words[0] == "HELO":
                if words[1] != "2":
                    print "LOG\tUnknown version", words[1]
                    print "FAIL"
                else:
                    print "OK\tGU Dynamic DNS Resolution Backend."
                    syslog.syslog('received HELO from PowerDNS')
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
        for record in qNameSet:
            rQType, ttl, content = record
            if qType in (rQType, 'ANY', 'AXFR'):
                answer = "DATA\t%s\t%s\t%s\t%d\t%d\t%s" % (qName, 'IN', rQType, ttl, int(qId), content)
                syslog.syslog('answerRecord: Printing answer: %s'%answer)
                print answer
    
    def query(self, (qName, qClass, qType, qId, remoteIp, localIp)):
        syslog.syslog('parsing query: %s %s %s %s %s %s'%(qName, qClass, qType, qId, remoteIp, localIp))
        if qClass == 'IN' and qName.lower() in self.dns_records:
            self.answerRecord(self.dns_records[qName.lower()], (qName, qClass, qType, qId, remoteIp, localIp))
        print "END"
    
    def axfr(self, id):
        for qName, qNameSet in self.dns_records.iteritems():
            answerRecord(qNameSet, (qName, "IN", "AXFR", id, "None", "None"), set())
        print "END"


    def __str__(self):
        return 'processInput Greenlet'
        
    
    
DNS_DATA = {
    'vips' : ["1.2.3.4","1.2.3.5"],
    'names' : ['example.com','www.example.com'],
    'records' : [('A', 300, "1.2.3.4"),('A', 300, "1.2.3.5"),],
    'records_lastresort' : [('A', 300, "1.2.3.4"),('A', 300, "1.2.3.5"),],
}

if __name__=="__main__":
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
    
    updater=UpdateRecords(DNS_DATA,probe_timeout=10,probe_interval=30)
    processor = ProcessInput(updater.dns_records)
    updater.processor=processor
    updater.start()
    processor.start()
    
    gevent.joinall([updater,processor])
    

