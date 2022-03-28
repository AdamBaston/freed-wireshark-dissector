# FreeD wireshark dissector
Dissect and read FreeD network packets according to the sony BRC-X1000 & BRC-X400 series camera specification. Position and rotation are decoded as meters and degrees, zoom and focus are the raw values and may not correspond to actual zoom/focus level. Iris is shown as the current F stop and the timestamp should always increment with each new packet received (unless wrapping around).
 
Please note - as of 2022/03/29 this has **not** been tested directly against a broadcasting BRC series camera and additional data sent is not supported (if you need this, message me and I can add this is in)
# Usage
Place the lua dissector file in the Wireshark personal plugins folder. 

Packets on port 6000 will be decoded as FreeD packets by default. To decode packets from another address/port, right-click on a packet and select "Decode As...". In the "Current" column, select "FreeD".




