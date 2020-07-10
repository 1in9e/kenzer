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
    
    #removes old log files
    def remolog(self):
        os.system("rm {0}/*.old".format(self.path))

    #enumerates subdomains
    def subenum(self):
        self.subfinder()
        self.shuffledns()
        domain = self.domain
        path = self.path
        out=path+"/subenum.kenz"
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/subfinder.log* {0}/subenum.kenz* {0}/shuffledns.log* | sort -u > {1}".format(path, out))
        #counts = str(sum(1 for line in open(out)))
        #return "successfully gathered {0} subdomains for: {1}".format(counts, domain)
        return("completed subenum for: "+domain) 
    
    #enumerates subdomains using subfinder
    #"retains wildcard domains" - retaining the possibilities of takeover detection via DNS e.g. AZURE
    def subfinder(self):
        domain = self.domain
        path = self.path
        path+="/subfinder.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("subfinder -t 20 -max-time 500 -o {0} -v -timeout 20 -d {1}".format(path, domain))
        return

    #enumerates subdomains using shuffledns
    #"removes wildcard domains" - eliminating the possibilities of takeover detection via DNS e.g. AZURE
    def shuffledns(self):
        domain = self.domain
        path = self.path
        path+="/shuffledns.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("shuffledns -r wordlists/resolvers.txt -w wordlists/shuffledns.txt -wt 100 -o {0} -v -d {1}".format(path, domain))
        return 

    #probes for web servers from enumerated subdomains
    def probeserv(self):
        if(os.path.exists(self.path+"/subenum.kenz") == False):
            return("run subenum")
        self.httpx()
        domain = self.domain
        path = self.path
        out = path+"/probeserv.kenz"
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/httpx.log* | cut -d' ' -f 1 | sort -u > {1}".format(path, out))
        #counts = str(sum(1 for line in open(out))) 
        #return "successfully probed "+counts+" servers for: "+domain
        return("completed probeserv for: "+domain) 

    #probes for web servers from enumerated subdomains using httpx
    def httpx(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        path+="/httpx.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("httpx -status-code -l {0} -threads 100 -ports 80,443,8080,8000 -retries 2 -timeout 10 -verbose -o {1}".format(subs, path))
        return

    #enumerates open ports using naabu
    def portenum(self):
        if(os.path.exists(self.path+"/subenum.kenz") == False):
            return("run subenum")
        self.shuffsolv()
        domain = self.domain
        path = self.path
        output = path+"/portenum.kenz"
        subs = path+"/shuffsolv.log"
        os.system("naabu -hL {0} -ports {4} -retries {5} -rate {6} -timeout {7} -json -o {1} -v -t {2} ".format(subs, output, 4, "top-1000", 2, 200, 2000))
        return("completed portenum for: "+domain)

    #resolves & removes wildcard subdomains using shuffledns
    def shuffsolv(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        path+="/shuffsolv.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("shuffledns -r wordlists/resolvers.txt -wt 100 -o {0} -v -list {1}".format(path, subs))
        return 
