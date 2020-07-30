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
        os.system("nuclei -c {0} -t {5}nuclei/{1} -v -timeout {2} -l {3} -o {4}".format(threads, template, timeout, hosts, output, self.templates))
        return
    
    #runs jaeles
    def jaeles(self, threads, template, timeout, hosts, output):
        os.system("jaeles scan --no-background --no-output -c {0} -s {5}jaeles/{1}/.* --timeout {2} -U {3} -O {4} -v ".format(threads, template, timeout, hosts, output, self.templates))
        return

    #checks for subdomain takeovers using nuclei
    def subover(self):
        domain = self.domain
        path = self.path
        output = path+"/suboverWEB.log"
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        self.nuclei(100, "subover/web", 15, subs, output)
        output = path+"/suboverDNS.log"
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum for: "+self.domain)
        self.nuclei(100, "subover/dns/subdomain-takeover-dns.yaml", 15, subs, output)
        output = path+"/suboverDNSWILD.log"
        self.nuclei(100, "subover/dns/subdomain-takeover-dns-wildcards.yaml", 15, subs, output)
        return("completed subover for: "+domain) 

    #checks for CVEs using nuclei & jaeles
    def cvescan(self):
        domain = self.domain
        path = self.path
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        output = path+"/cvescanDOMN.log"
        self.nuclei(100, "cvescan", 15, subs, output)
        output = path+"/cvescanDOMJ.log"
        self.jaeles(100, "cvescan", 15, subs, output)
        subs = path+"/urlenum.kenz"
        if(os.path.exists(subs)):
            output = path+"/cvescanURLN.log"
            self.nuclei(100, "cvescan", 15, subs, output)
            output = path+"/cvescanURLJ.log"
            self.jaeles(100, "cvescan", 15, subs, output)
        return("completed cvescan for: "+domain)

    #checks for other common vulnerabilities using nuclei & jaeles
    def vulnscan(self):
        domain = self.domain
        path = self.path
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        output = path+"/vulnscanDOMN.log"
        self.nuclei(100, "vulnscan", 15, subs, output)
        output = path+"/vulnscanDOMJ.log"
        self.jaeles(100, "vulnscan", 15, subs, output)
        subs = path+"/urlenum.kenz"
        if(os.path.exists(subs)):
            output = path+"/vulnscanURLN.log"
            self.nuclei(100, "vulnscan", 15, subs, output)
            output = path+"/vulnscanURLJ.log"
            self.jaeles(100, "vulnscan", 15, subs, output)
        return("completed vulnscan for: "+domain)