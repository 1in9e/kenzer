# KENZER | A Zulip Chatbot
![](/images/logo.png)

## Instructions for running
1. Create an account on [Zulip](https://zulipchat.com)<br>
2. Navigate to ` Settings > Your Bots > Add a new bot `<br>
3. Create a new generic bot named 'kenzer'<br>
4. Clone this repository using ` git clone https://github.com/g147/Kenzer.git `<br>
5. Add all the configurations in  ` kenzer.conf `<br>
6. Install & Configure following tools manually.<br>
	a. `python3`<br>
	b. `nuclei`<br>
	c. `httpx`<br>
	d. `subfinder`<br>
	e. `massdns`<br>
	f. `shuffledns`<br>
7. Install & run using ` bash install.sh ` or just run using ` bash run.sh `<br>
8. You can interact with **KENZER** using multi-platform Zulip Clients.<br>

## Built-in Functionalities
>* Enumerates subdomains<br>
>* Probes web servers from the enumerated subdomains<br>
>* Checks for Subdomain Takeovers<br>
>* Checks for CVEs<br>
>* Checks for other common vulnerabilites<br>
>* Chats using ChatterBot Conversational Engine<br>


