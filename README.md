# freed-wireshark-dissector
Dissect and read FreeD network packets. Position and rotation are decoded as meters and degrees, zoom and focus are the raw values and may not correspond to actual zoom/focus level.

I do not know what the spare field corresponds to, any help would be greatly appriciated, and any additional data being sent is not supported 

# Usage
Place the lua dissector file in the Wireshark personal plugins folder. 
Packets on port 6000 will be decoded as FreeD packets. To decode packets from another address/port, right-click on a packet and select "Decode As...". In the "Current" column, select "FreeD".




