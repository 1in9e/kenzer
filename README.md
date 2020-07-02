# KENZER | A Zulip Chatbot
![](/images/logo.png)

## Instructions for running:
1. Create an account on [Zulip](https://zulipchat.com)
2. Navigate to ` Settings > Your Bots > Add a new bot `
3. Create a new generic bot named 'kenzer'
4. Clone this repository using ` git clone https://github.com/g147/Kenzer.git `
5. Add all the configurations in  ` kenzer.conf `
6. Install & Configure following tools manually.
    a. `python3`
	b. `nuclei`
	c. `httpx`
	d. `subfinder`
7. Install & run using ` bash install.sh ` or just run using ` bash run.sh `
8. You can interact with **KENZER** using multi-platform Zulip Clients.

## Functions
>* Enumerates subdomains
>* Probes web servers from the enumerated subdomains
>* Checks for Subdomain Takeovers
>* Checks for CVEs
>* Chats using ChatterBot Conversational Engine


