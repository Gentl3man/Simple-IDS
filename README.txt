Author: Giorgos Dovas
Linkedin: https://www.linkedin.com/in/giorgos-dovas-208a3523b/
IDS, it reads packets from a pcap file and checks their ip addresses and ports, 
from the source and the destination. Now if the packe's IPs and ports match a rule
then the IDS prints a message (alert) to the file alerts.txt.

The program by default reads the rules from teh IDS_Filter_Rules file, you can 
either edit the rules in the file, or choose another .txt rule file if you wish.

The way rules are stored. First IPs are saved a string and when the rule is valid
I cast them into ints using bitwise operations to save all the bits. The reason
I do this is to ignore the "mask" bits by right shifting the (now int) IPs.
After that a simple comparisson is enough to decide if the packet match any of the rules.