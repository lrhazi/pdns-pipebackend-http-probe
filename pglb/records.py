from gevent import sleep, Greenlet
import urllib2
import syslog, os
import logging
logger = logging.getLogger()

__all__ = ['Records']

class Records(Greenlet):
    
    def __init__(self,config_filename, interval=30):
        Greenlet.__init__(self)
        self.config_filename = config_filename
        self.configfile_lastMTime = None
        self.processor = None
        self.qnames = []
        self.configs=[]
        self.data = {}
        self.monitors = {}
        self.reloaded = False
        self.interval = interval
        
    def _run(self):
        while True:
            if self.processor.dead:
                logger.info('processor greenlet died. exiting.')
                break
            self._reload() and self._rebuild()
            [x.start() for x in self.monitors.values() if not x.started]
            sleep(self.interval)
            if self.reloaded:
                self._cleanup_monitors()
                self.reloaded = False
        
    def _rebuild(self):
        new_qnames = [ x[0] for x in self.configs]
        self._remove_qnames([ x for x in self.qnames if not x in new_qnames])
        for e in self.configs:
            self.update_qname(e)
            sleep(0)
        self.reloaded = True

    def _reload(self):
        """
        www.glb.georgetown.edu,A,300,1.2.3.4|2.3.4.5,RR,http,80,15,31,1.2.3.4|2.3.4.5
        """

        try:
            curMTime = os.path.getmtime(self.config_filename)
            if self.configfile_lastMTime is None or self.configfile_lastMTime != curMTime:
                self.configfile_lastMTime = curMTime
            else:
                return False
                
            configs = []
            with open(self.config_filename) as f:
                for line in f:
                    c={}
                    line = line.strip()
                    if len(line) == 0 or line.startswith('#'): continue
                    (qname,qtype,ttl,vips,lb_method,
                        monitor_protocol,monitor_port,monitor_interval,monitor_timeout,
                        vips_lastresort) = line.split(',')
                    
                    qname = qname
                    qtype = qtype
                    ttl = int(ttl)
                    vips = [x for x in vips.split('|') if x]
                    lb_method = lb_method
                    monitor_protocol = monitor_protocol
                    monitor_port = int(monitor_port) 
                    monitor_interval = int(monitor_interval)
                    monitor_timeout = int(monitor_timeout)
                    vips_lastresort = [x for x in vips_lastresort.split('|') if x]
                    assert(len(qname)>3)
                    assert(qtype in ('A','AAAA'))
                    assert(ttl>0)
                    assert(len(vips)>0)
                    assert(lb_method=="RR")
                    assert(monitor_protocol in ['http','https'])
                    assert(monitor_port > 0)
                    assert(monitor_interval > 0)
                    assert(monitor_timeout > 0)
                    assert(len(vips_lastresort)>0)
                    configs.append((qname,qtype,ttl,vips,lb_method,
                        monitor_protocol,monitor_port,monitor_interval,monitor_timeout,
                        vips_lastresort))
            logger.info("Loaded configuration file: %s"%self.config_filename)
            self.configs = configs
            return True
        except Exception,e:
            print("LOG\tCould not load configuration file: %s: Exception: %s"%(self.config_filename,e))
            return False

    
    def _remove_qnames(self,qnames):
        for qname in qnames:
            logger.info('Removing qname: %s'%qname)
            del(self.data[qname])
            self.qnames.remove(qname)
            
    def _cleanup_monitors(self):
        for m_name,m in self.monitors.items():
            stale = True
            for qname in m.qnames:
                if self.data.has_key(qname):
                    for records in self.data[qname][0]:
                        if m is records[4]:
                            stale = False
            if stale:
                logger.info('Removing monitor: %s: %s'%(m_name,m))
                m.kill()
                del(self.monitors[m_name])

    def update_qname(self,q):
        (qname,qtype,ttl,vips,lb_method,
            monitor_protocol,monitor_port,monitor_interval,monitor_timeout,
            vips_lastresort) = q
        if not qname in self.qnames:
            self.qnames.append(qname)
        records = []
        for vip in vips:
            monitor = "%s:%s:%s"%(monitor_protocol,vip,monitor_port)
            if not self.monitors.has_key(monitor):
                m = Monitor(monitor_protocol,vip,monitor_port,monitor_interval,monitor_timeout)
                m.qnames.add(qname)
                self.monitors[monitor] = m
                logger.info('Created monitor: %s'%m)
            else:
                self.monitors[monitor].interval = monitor_interval
                self.monitors[monitor].timeout = monitor_timeout
                self.monitors[monitor].qnames.add(qname)
            records.append( (qtype,ttl,vip,lb_method,self.monitors[monitor]) )
        self.data[qname] = (records,vips_lastresort)

            
class Monitor(Greenlet):
    def __init__(self,protocol,vip,port,interval,timeout,uri="/"):
        Greenlet.__init__(self)
        self.up=True
        self.ip = vip
        self.protocol = protocol
        self.port = port
        self.uri = uri
        self.interval = interval
        self.timeout = timeout
        self.qnames = set()

    def _run(self):
        while True:
            previous_state = self.up
            self.up = self.probe_http()
            if self.up != previous_state:
                if not self.up:
                    logger.error(self)
                else:
                    logger.info(self)
            sleep(self.interval)

    def probe_http(self):
        url = '%s://%s:%d%s' % (self.protocol,self.ip,self.port,self.uri)
        ok=False
        try:
            r=urllib2.urlopen(url,None,self.timeout)
            ok = True
        except urllib2.URLError,e:
            #logger.debug("%s: %s"%(self,e))
            pass
        except urllib2.HTTPError,e:
            #logger.error("%s: %s"%(self,e))
            pass
        finally:
            return ok
    
    def __str__(self):
        return 'Monitor (%s:%s) (%s) (%s) UP: %s'%(self.ip,self.port,self.qnames,id(self),self.up)
