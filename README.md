# FreeD wireshark dissector
Dissect and read FreeD network packets. Position and rotation are decoded as meters and degrees, zoom and focus are the raw values and may not correspond to actual zoom/focus level.

I don't know what the spare field corresponds to, any help would be greatly appreciated with deciding what it is for. Any additional fields of data being sent will not be decoded.  

# Usage
Place the lua dissector file in the Wireshark personal plugins folder. 

Packets on port 6000 will be decoded as FreeD packets. To decode packets from another address/port, right-click on a packet and select "Decode As...". In the "Current" column, select "FreeD".




