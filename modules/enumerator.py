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
        domain = self.domain
        path = self.path
        out=path+"/subenum.kenz"
        if(os.path.exists(path)):
            os.system("mv "+out+" "+out+".old")
        os.system("cat "+path+"/subfinder.log* | sort -u > "+out)
        os.system("rm "+path+"/*.old")
        counts = str(sum(1 for line in open(out)))
        return "successfully gathered "+counts+" subdomains for: "+domain

    #probes for web servers from enumerated subdomains
    def probeserv(self):
        self.httpx()
        domain = self.domain
        path = self.path
        out = path+"/probeserv.kenz"
        if(os.path.exists(out)):
            os.system("mv "+out+" "+out+".old")
        os.system("cat "+path+"/httpx.log* | sort -u > "+out)
        os.system("rm "+path+"/*.old")
        counts = str(sum(1 for line in open(out))) 
        return "successfully probed "+counts+" servers for: "+domain
    
    #enumerates subdomains using subfinder
    def subfinder(self):
        domain = self.domain
        path = self.path
        path+="/subfinder.log"
        if(os.path.exists(path)):
            os.system("mv "+path+" "+path+".old")
        os.system("subfinder -t 20 -max-time 500 -o "+path+" -v -timeout 20 -d "+domain)
        return 

    #probes for web servers from enumerated subdomains using httpx
    def httpx(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("run subenum")
        path+="/httpx.log"
        if(os.path.exists(path)):
            os.system("mv "+path+" "+path+".old")
        os.system("cat "+subs+" | httpx -threads 100 -retries 2 -timeout 10 -verbose -o "+path)
        return
