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

    #checks for subdomain takeovers
    def subover(self):
        domain = self.domain
        path = self.path
        output = path+"/suboverWEB.log"
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv")
        os.system("nuclei -c 40 -t templates/subover/detect-all-takeovers.yaml -v -timeout 20 -l "+subs+" -o "+output)
        output = path+"/suboverDNS.log"
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum")
        os.system("nuclei -c 40 -t templates/subover/subdomain-takeover-dns.yaml -v -timeout 20 -l "+subs+" -o "+output)
        output = path+"/suboverDNS2.log"
        os.system("nuclei -c 40 -t templates/subover/subdomain-takeover-dns-wildcards.yaml -v -timeout 20 -l "+subs+" -o "+output)
        return("completed subover for: "+domain) 


    #checks for CVEs
    def cvescan(self):
        domain = self.domain
        path = self.path
        output = path+"/cvescan.log"
        subs = path+"/probeserv.kenz"
        if(os.path.exists(subs) == False):
            return("run probeserv")
        os.system("nuclei -c 40 -t templates/cvescan -v -timeout 20 -l "+subs+" -o "+output)
        return("completed cvescan for: "+domain)

    
