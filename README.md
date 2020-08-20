# KENZER | A Zulip Chatbot
### not innovation. just automation.
![](/images/logo.png)

## Instructions for running
1. Create an account on [Zulip](https://zulipchat.com)<br>
2. Navigate to `Settings > Your Bots > Add a new bot`<br>
3. Create a new generic bot named `kenzer`<br>
4. Clone this repository using `git clone https://github.com/g147/kenzer.git`<br>
5. Add all the configurations in `configs/kenzer.conf`<br>
6. Install & run using `./install.sh` or just run using `./run.sh`<br>
7. You can interact with **KENZER** using multi-platform Zulip Clients.<br>
8. **KENZERDB** can be cloned using `git clone https://github.com/g147/kenzerdb.git`<br>
9. `kenzer man` as input can be used to display the user manual while interaction.<br>

## Built-in Functionalities
>* Enumerates subdomains(subenum)<br>
>* Probes web servers from the enumerated subdomains(probeserv)<br>
>* Fingerprints using favicon(favinize)<br>
>* Hunts for open S3 bucket(s3hunt)<br>
>* Enumerates open ports(portenum)<br>
>* Enumerates urls(urlenum)<br>
>* Hunts for Subdomain Takeovers(subover)<br>
>* Hunts for CVEs(cvescan)<br>
>* Hunts for other common vulnerabilities(vulnscan)<br>
>* Chats using ChatterBot Conversational Engine<br>

![](/images/webhunt.jpg)

**COMPATIBILITY TESTED ON ARCHLINUX(x64) ONLY**<br>
**FEEL FREE TO SUBMIT PULL REQUESTS**