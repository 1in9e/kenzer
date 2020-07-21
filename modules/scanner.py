#imports
import os
import time

#scanner
class Scanner:
    
    #initializations
    def __init__(self,domain,db):
        self.domain = domain
        self.organization = domain.replace(".","")
        self.path = db+self.organization
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    #runs nuclei
    def nuclei(self, threads, template, timeout, hosts, output):
        os.system("nuclei -c {0} -t templates/{1} -v -timeout {2} -l {3} -o {4}".format(threads, template, timeout, hosts, output))
        return

    #checks for subdomain takeovers
    def subover(self):
        domain = self.domain
        path = self.path
        output = path+"/suboverWEB.log"
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        self.nuclei(40, "subover/detect-all-takeovers.yaml", 20, subs, output)
        output = path+"/suboverDNS.log"
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum for: "+self.domain)
        self.nuclei(40, "subover/subdomain-takeover-dns.yaml", 20, subs, output)
        output = path+"/suboverDNSWILD.log"
        self.nuclei(40, "subover/subdomain-takeover-dns-wildcards.yaml", 20, subs, output)
        return("completed subover for: "+domain) 

    #checks for CVEs
    def cvescan(self):
        domain = self.domain
        path = self.path
        output = path+"/cvescanDOM.log"
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        self.nuclei(40, "cvescan", 20, subs, output)
        output = path+"/cvescanURL.log"
        subs = path+"/urlenum.kenz"
        #if(os.path.exists(subs) == False):
            #return("run urlenum for: "+self.domain)
        #self.nuclei(40, "cvescan", 20, subs, output)
        if(os.path.exists(subs)):
            self.nuclei(40, "cvescan", 20, subs, output)
        return("completed cvescan for: "+domain)

    #checks for other common vulnerabilities
    def vulnscan(self):
        domain = self.domain
        path = self.path
        output = path+"/vulnscanDOM.log"
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv for: "+self.domain)
        self.nuclei(40, "vulnscan", 20, subs, output)
        output = path+"/vulnscanURL.log"
        subs = path+"/urlenum.kenz"
        #if(os.path.exists(subs) == False):
        #    return("run urlenum for: "+self.domain)
        #self.nuclei(40, "vulnscan", 20, subs, output)
        if(os.path.exists(subs)):
            self.nuclei(40, "vulnscan", 20, subs, output)
        return("completed vulnscan for: "+domain) 