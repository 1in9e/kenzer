#imports
import zulip
import time
import os
import sys

from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer
from configparser import ConfigParser

from modules import enumerator
from modules import scanner

#configs
try:
    conf = "configs/kenzer.conf"
    config = ConfigParser()
    with open(conf) as f:
         config.read_file(f, conf)
    _BotMail=config.get("zulip", "email")
    _Site=config.get("zulip", "site")
    _APIKey=config.get("zulip", "key")
    _kenzer=config.get("env", "kenzer")
    _kenzerdb=config.get("env", "kenzerdb")
    _home=config.get("env", "home")
    _chaos=config.get("env", "chaos")
    _github=config.get("env", "github")
    os.chdir(_kenzer)
    os.environ["HOME"] = _home
    if(os.path.exists(_kenzerdb) == False):
        os.system("mkdir "+_kenzerdb)
except:
    sys.exit("[*] invalid configurations")

#kenzer 
class Kenzer(object):
    
    #initializations
    def __init__(self):
        print("[*] initializing kenzer")
        self.client = zulip.Client(email=_BotMail, site=_Site, api_key=_APIKey)
        #self.subscribe()
        print("[*] training chatterbot")
        self.chatbot = ChatBot("Kenzer")
        self.trainer = ChatterBotCorpusTrainer(self.chatbot)
        self.trainer.train("chatterbot.corpus.english")
        self.upload=True
        print("[*] loading modules")
        #self.modules=["man", "subenum", "probeserv", "favinize", "portenum", "urlenum", "subover", "cvescan", "vulnscan", "s3hunt", "enum", "scan", "recon", "remlog", "upload"]
        print("[*] KENZER is online")

    #subscribes to all streams
    def subscribe(self):
        try:
            json=self.client.get_streams()["streams"]
            streams=[{"name":stream["name"]} for stream in json]
            self.client.add_subscriptions(streams)
        except:
            print("[*] an exception occurred.... retrying....")
            self.subscribe()

    #manual
    def man(self):
        message = "**KENZER is online**\n"
        message +="  initializations successful\n"
        message +="  15 modules up & running\n"
        message +="**KENZER modules**\n"
        message +="  `subenum` - enumerates subdomains\n"
        message +="  `probeserv` - probes web servers from enumerated subdomains\n"
        message +="  `portenum` - enumerates open ports\n"
        message +="  `urlenum` - enumerates urls\n"
        message +="  `subover` - hunts for subdomain takeovers\n"
        message +="  `cvescan` - hunts for CVEs\n"
        message +="  `vulnscan` - hunts for common vulnerabilites\n"
        message +="  `s3hunt` - hunts for unreferenced aws s3 buckets\n"
        message +="  `favinize` - fingerprints using favicon\n"
        message +="  `enum` - runs all enumerator modules\n"
        message +="  `scan` - runs all scanner modules\n"
        message +="  `recon` - runs all modules\n"
        message +="  `hunt` - runs your custom workflow\n"
        message +="  `remlog` - removes log files\n"
        message +="  `upload` - switches upload functionality\n"
        message +="`kenzer <module>` - runs a specific modules\n"
        message +="`kenzer man` - shows this manual\n"
        message +="`kenzer man <module>` - shows manual for a specific module\n"
        message +="or you can just interact with chatterbot\n"
        self.sendMessage(message)
        return
    
    #modules manual
    def manModule(self, module):
        if module == "subenum":
            message ="`kenzer subenum <domain>` - enumerates subdomains of the given domain\n"
        elif module == "probeserv":
            message ="`kenzer probeserv <domain>` - probes web servers for enumerated subdomains of the given domain\n"
        elif module == "portenum":
            message ="`kenzer portenum <domain>` - enumerates open ports for enumerated subdomains of the given domain\n"
        elif module == "urlenum":
            message ="`kenzer urlenum <domain>` - enumerates urls of the given domain\n"
        elif module == "subover":
            message ="`kenzer subover <domain>` - hunts for subdomain takeover possibilites of the given domain\n"
        elif module == "cvescan":
            message ="`kenzer cvescan <domain>` - checks if subdomains/urls of the given domain are vulnerable to known CVEs\n"
        elif module == "vulnscan":
            message ="`kenzer vulnscan <domain>` - checks if subdomains/urls of the given domain are vulnerable to other common vulnerabilities\n"
        elif module == "s3hunt":
            message ="`kenzer s3hunt <domain>` - hunts for unreferenced aws s3 buckets of the given domain \n"
        elif module == "favinize":
            message ="`kenzer favinize <domain>` - fingerprints probed web servers using favicon\n"
        elif module == "enum":
            message ="`kenzer enum <domain>` - runs all enumerator modules on given domain\n"
        elif module == "scan":
            message ="`kenzer scan <domain>` - runs all scanner modules on given domain\n"
        elif module == "hunt":
            message ="`kenzer hunt <domain>` - runs your custom workflow on given domain\n"
        elif module == "recon":
            message ="`kenzer recon <domain>` - runs all modules on given domain\n"
        elif module == "remlog":
            message ="`kenzer remlog <domain>` - removes log files & empty files for given domain\n"
        elif module == "upload":
            message ="`kenzer upload` - turns upload on/off\n"
        else:
            message ="invalid module....\n"
        self.sendMessage(message)
        return

    #sends messages
    def sendMessage(self, message):
        time.sleep(2)
        if self.type == "private":
            self.client.send_message({
                "type": self.type,
                "to": self.sender_email,
                "content": message
            })
        else:
            self.client.send_message({
                "type": self.type,
                "subject": self.subject,
                "to": self.display_recipient,
                "content": message
            })
        time.sleep(3)
        return

    #uploads output
    def uploader(self, domain, raw):
        global _kenzerdb
        global _Site
        print(_kenzerdb)
        org=domain.replace(".","")
        data = _kenzerdb+org+"/"+raw
        print(data)
        if(os.path.exists(data) == False):
            return
        with open(data, 'rb') as fp:
            uploaded = self.client.call_endpoint(
            'user_uploads',
            method='POST',
            files=[fp],
        )
        self.sendMessage("{0}/{1} : {3}{2}".format(org, raw, uploaded['uri'], _Site))
        print(uploaded)

    #enumerates subdomains
    def subenum(self):
        for i in range(2,len(self.content)):
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _chaos, _github)
            message = self.enum.subenum()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "subenum.kenz")
        return

    #probes web servers from enumerated subdomains
    def probeserv(self):
        for i in range(2,len(self.content)):
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb)
            message = self.enum.probeserv()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "probeserv.kenz")
        return
    
    #enumerates open ports
    def portenum(self):
        for i in range(2,len(self.content)):
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb)
            message = self.enum.portenum()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "portenum.kenz")
        return
    #enumerates urls
    def urlenum(self):
        for i in range(2,len(self.content)):
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb, _chaos, _github)
            message = self.enum.urlenum()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "urlenum.kenz")
        return

    #hunts for subdomain takeovers
    def subover(self):
        for i in range(2,len(self.content)):
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.subover()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "subover.kenz")
        return

    #hunts for CVEs
    def cvescan(self):
        for i in range(2,len(self.content)):
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.cvescan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "cvescan.kenz")
        return
    
    #hunts for other common vulnerabilities
    def vulnscan(self):
        for i in range(2,len(self.content)):
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.vulnscan()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "vulnscan.kenz")
        return
    
    #hunts for subdomain takeovers
    def s3hunt(self):
        for i in range(2,len(self.content)):
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.s3hunt()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "s3hunt.kenz")
        return

    #fingerprints servers using favicons
    def favinize(self):
        for i in range(2,len(self.content)):
            self.scan = scanner.Scanner(self.content[i].lower(), _kenzerdb, _kenzer)
            message = self.scan.favinize()
            self.sendMessage(message)
            if self.upload:
                self.uploader(self.content[i], "favinize.kenz")
        return

    #runs all enumeration modules
    def enum(self):
        self.subenum()
        self.probeserv()
        self.portenum()
        self.urlenum()
        return

    #runs all scanning modules
    def scan(self):
        self.subover()
        self.favinize()
        self.s3hunt()
        self.cvescan()
        self.vulnscan()
        return

    #define your custom workflow    
    def hunt(self):
        self.subenum()
        self.probeserv()
        self.subover()
        self.favinize()
        self.s3hunt()
        self.urlenum()
        #manual audit required for urlenum
        self.cvescan()
        self.vulnscan()
        self.portenum()
        self.remlog()

    #runs all modules
    def recon(self):
        self.enum()
        self.scan()
        return
    
    #removes old log files
    def remlog(self):
        for i in range(2,len(self.content)):
            self.enum = enumerator.Enumerator(self.content[i].lower(), _kenzerdb)
            message = self.enum.remlog()
            self.sendMessage(message)
        return

    #controls
    def process(self, text):
        self.content = text["content"].split()
        self.sender_email = text["sender_email"]
        self.type = text["type"]
        self.display_recipient = text['display_recipient']
        self.subject = text['subject']
        content=self.content
        print(content)
        if self.sender_email == _BotMail:
            return
        if len(content)>1 and content[0].lower() == "kenzer" or content[0] == "@**kenzer**":
            if content[1].lower() == "man":
                if len(content)==2:
                    self.man()
                elif len(content)==3:
                    self.manModule(content[2])
                else:
                    message = "excuse me???"
                    self.sendMessage(message)    
            elif content[1].lower() == "subenum":
                self.subenum()
            elif content[1].lower() == "probeserv":
                self.probeserv()
            elif content[1].lower() == "favinize":
                self.favinize()
            elif content[1].lower() == "portenum":
                self.portenum()
            elif content[1].lower() == "urlenum":
                self.urlenum()
            elif content[1].lower() == "subover":
                self.subover()
            elif content[1].lower() == "cvescan":
                self.cvescan()
            elif content[1].lower() == "vulnscan":
                self.vulnscan()
            elif content[1].lower() == "s3hunt":
                self.s3hunt()
            elif content[1].lower() == "enum":
                self.enum()
            elif content[1].lower() == "scan":
                self.scan()
            elif content[1].lower() == "hunt":
                self.hunt()
            elif content[1].lower() == "recon":
                self.recon()
            elif content[1].lower() == "remlog":
                self.remlog()
            elif content[1].lower() == "upload":
                self.upload = not self.upload
                self.sendMessage("upload: "+str(self.upload))
            else:
                message = "excuse me??"
                self.sendMessage(message)
        else:
            message = self.chatbot.get_response(' '.join(self.content))
            message = message.serialize()['text']
            self.sendMessage(message)
        return    

#main
def main():
    bot = Kenzer()
    bot.client.call_on_each_message(bot.process)

#runs main
if __name__ == "__main__":
    main()
