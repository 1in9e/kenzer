#imports
import os

#enumerator
class Enumerator:
    
    #initializations
    def __init__(self,domain,db):
        self.domain = domain
        self.organization = domain.replace(".","")
        self.path = db+self.organization
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    #enumerates subdomains
    def subenum(self):
        self.subfinder()
        self.shuffledns()
        domain = self.domain
        path = self.path
        out=path+"/subenum.kenz"
        if(os.path.exists(out)):
            os.system("mv "+out+" "+out+".old")
        os.system("cat "+path+"/subfinder.log* "+path+"/subenum.kenz* "+path+"/shuffledns.log* | sort -u > "+out)
        os.system("rm "+path+"/*.old")
        counts = str(sum(1 for line in open(out)))
        return "successfully gathered "+counts+" subdomains for: "+domain

    #probes for web servers from enumerated subdomains
    def probeserv(self):
        if(os.path.exists(self.path+"/subenum.kenz") == False):
            return("run subenum")
        self.httpx()
        domain = self.domain
        path = self.path
        out = path+"/probeserv.kenz"
        if(os.path.exists(out)):
            os.system("mv "+out+" "+out+".old")
        os.system("cat "+path+"/httpx.log* | cut -d' ' -f 1 | sort -u > "+out)
        #os.system("rm "+path+"/*.old")
        counts = str(sum(1 for line in open(out))) 
        return "successfully probed "+counts+" servers for: "+domain
    
    #enumerates subdomains using subfinder
    #"retains wildcard domains" - retaining the possibilities of takeover detection via DNS e.g. AZURE
    def subfinder(self):
        domain = self.domain
        path = self.path
        path+="/subfinder.log"
        if(os.path.exists(path)):
            os.system("mv "+path+" "+path+".old")
        os.system("subfinder -t 20 -max-time 500 -o "+path+" -v -timeout 20 -d "+domain)
        return 
    
    #enumerates subdomains using shuffledns
    #"removes wildcard domains" - eliminating the possibilities of takeover detection via DNS e.g. AZURE
    def shuffledns(self):
        domain = self.domain
        path = self.path
        path+="/shuffledns.log"
        if(os.path.exists(path)):
            os.system("mv "+path+" "+path+".old")
        os.system("shuffledns -r wordlists/resolvers.txt -w wordlists/shuffledns.txt -wt 100 -o "+path+" -v -d "+domain)
        return 

    #probes for web servers from enumerated subdomains using httpx
    def httpx(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        path+="/httpx.log"
        if(os.path.exists(path)):
            os.system("mv "+path+" "+path+".old")
        os.system("httpx -status-code -l "+subs+" -threads 100 -ports 80,443,8080,8000 -retries 2 -timeout 10 -verbose -o "+path)
        return
