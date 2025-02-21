#imports
import os
import time

#scanner
class Scanner:
    
    #initializations
    def __init__(self, domain, db, kenzer):
        self.domain = domain
        self.organization = domain.replace(".","")
        self.path = db+self.organization
        self.templates = kenzer+"templates/"
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    #runs nuclei
    def nuclei(self, threads, template, timeout, hosts, output):
        os.system("nuclei -pbar -c {0} -t {5}nuclei/{1}  -v -timeout {2} -l {3} -o {4}".format(threads, template, timeout, hosts, output, self.templates))
        return
    
    #runs jaeles
    def jaeles(self, threads, template, timeout, hosts, output):
        os.system("jaeles scan --no-background --no-output -c {0} -s {5}jaeles/{1}/.* --timeout {2} -U {3} -O {4} -v ".format(threads, template, timeout, hosts, output, self.templates))
        return

    #hunts for subdomain takeovers using nuclei
    def subover(self):
        domain = self.domain
        path = self.path
        output = path+"/suboverWEB.log"
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        self.nuclei(100, "subover/web", 7, subs, output)
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum for: "+self.domain)
        output = path+"/suboverDNS.log"
        self.nuclei(100, "subover/dns/subdomain-takeover-dns.yaml", 7, subs, output)
        output = path+"/suboverDNSWILD.log"
        self.nuclei(100, "subover/dns/subdomain-takeover-dns-wildcards.yaml", 7, subs, output)
        out = path+"/subover.kenz"
        os.system("cat {0}/subover* | sort -u > {1}".format(path, out))
        return("completed subover for: "+domain) 

    #hunts for CVEs using nuclei & jaeles
    def cvescan(self):
        domain = self.domain
        path = self.path
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        output = path+"/cvescanDOMN.log"
        self.nuclei(100, "cvescan", 7, subs, output)
        output = path+"/cvescanDOMJ.log"
        self.jaeles(100, "cvescan", 7, subs, output)
        subs = path+"/urlenum.kenz"
        if(os.path.exists(subs)):
            output = path+"/cvescanURLN.log"
            self.nuclei(100, "cvescan", 7, subs, output)
            output = path+"/cvescanURLJ.log"
            self.jaeles(100, "cvescan", 7, subs, output)
        out = path+"/cvescan.kenz"
        os.system("cat {0}/cvescan* | sort -u > {1}".format(path, out))
        return("completed cvescan for: "+domain)

    #hunts for other common vulnerabilities using nuclei & jaeles
    def vulnscan(self):
        domain = self.domain
        path = self.path
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        output = path+"/vulnscanDOMN.log"
        self.nuclei(100, "vulnscan", 7, subs, output)
        output = path+"/vulnscanDOMJ.log"
        self.jaeles(100, "vulnscan", 7, subs, output)
        subs = path+"/urlenum.kenz"
        if(os.path.exists(subs)):
            output = path+"/vulnscanURLN.log"
            self.nuclei(100, "vulnscan", 7, subs, output)
            output = path+"/vulnscanURLJ.log"
            self.jaeles(100, "vulnscan", 7, subs, output)
        out = path+"/vulnscan.kenz"
        os.system("cat {0}/vulnscan* | sort -u > {1}".format(path, out))
        return("completed vulnscan for: "+domain)

    #hunts for unreferenced aws s3 buckets using s3hunter
    def s3hunt(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum for: "+self.domain)
        output = path+"/s3huntDirect.log"
        os.system("s3-hunter -l {0} -t 7 -T 100 -o {1} --only-direct".format(subs, output))
        output = path+"/iperms.log"
        os.system("s3-hunter -l {0} -o {1} -P".format(subs, output))
        subs = output
        output = path+"/s3huntPerms.log"
        self.nuclei(100, "subover/web/s3-hunter.yaml", 7, subs, output)
        out = path+"/s3hunt.kenz"
        os.system("cat {0}/s3hunt* | sort -u > {1}".format(path, out))
        return("completed s3hunt for: "+domain)
    
    #fingerprints probed servers using favinizer
    def favinize(self):
        domain = self.domain
        path = self.path
        out = path+"/favinize.kenz"
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("favinizer -d {2}/favinizer.yaml -t 7 -T 100 -l {0} -o {1}".format(subs, out, self.templates))
        return("completed favinize for: "+domain) 
