# CSC Project2 - MITM and Pharming Attacks in Wi-Fi Networks

## Tasks: MITM and Pharming

### MITM Attack (60%)
 
> 1. Task I: 20%
    Obtain all other client devices’ IP/MAC addresses in a connected Wi-Fi network
> 2. Task II: 15%
    ARP spoofing for all other client devices in the Wi-Fi network 
> 3. Task III: 15%
    Fetch the inputted username/password strings from HTTP sessions
> 4. (10%) One implementation question during the demo 


#### > **solution** : source/mitm_attack.cpp


### Pharming Attack (40%)

> 1. Obtain all other client devices’ IP/MAC addresses in a connected Wi-Fi network
> 2. Task IV: 30%
    DNS spoofing attack for web services 
> 3. (10%) One implementation question during the demo


#### > **solution** : source/pharm_attack.cpp


> Note: 
> After `make` attacker the service ip_forward is open and send_redirects is closed, so that the ARP spoofing can work successfully.
> The program **mitm_attack** will update the arp table of attacker immediately.
> running mitm_attack and pharm_attack's command: `sudo ./mitm_attack` and  `sudo ./pharm_attack`.