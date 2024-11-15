-- MIT License

-- Copyright (c) 2022 Adam Baston

-- Permission is hereby granted, free of charge, to any person obtaining a
-- copy of this software and associated documentation files (the "Software"),
-- to deal in the Software without restriction, including without limitation
-- the rights to use, copy, modify, merge, publish, distribute, sublicense,
-- and/or sell copies of the Software, and to permit persons to whom the
-- Software is furnished to do so, subject to the following conditions:

-- The above copyright notice and this permission notice shall be included
-- in all copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
-- EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
-- MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
-- IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
-- CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
-- TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
-- SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-- Copy the Lua dissector file to the Wireshark personal plugins folder.
-- Find this folder by looking in Help > About Wireshark > folders > Personal Lua Plugins
-- You may need to create this folder.


local freed_protocol = Proto("FreeD","FreeD protocol")

local message_type = ProtoField.uint8("freed.message_type","Message Type",base.HEX)
local camera_id = ProtoField.int32("freed.camera_id","Camera ID",base.DEC)

local pan = ProtoField.int32("freed.pan","Pan",base.DEC)
local tilt = ProtoField.int32("freed.tilt","Tilt",base.DEC)
local roll = ProtoField.int32("freed.roll","Roll",base.DEC)

local x = ProtoField.int32("freed.x","x",base.DEC)
local y = ProtoField.int32("freed.y","y",base.DEC)
local height = ProtoField.int32("freed.height","height",base.DEC)

local zoom = ProtoField.int32("freed.zoom","Zoom",base.DEC)
local focus = ProtoField.int32("freed.focus","Focus",base.DEC)


local user = ProtoField.uint32("freed.user","User",base.HEX)
local checksum = ProtoField.uint32("freed.checksum","Checksum", base.HEX)

freed_protocol.fields = {message_type, camera_id, pan, tilt, roll, x, y, height, zoom, focus, user, checksum}

function freed_protocol.dissector(buffer, pinfo, tree)
  -- Check if UDP payload could be a D1 packet
  if buffer:len() ~= 29 then return end
  if buffer(0,1):uint() ~= 0xD1 then return end
  
  pinfo.cols.protocol = freed_protocol.name
  
  local subtree = tree:add(freed_protocol, buffer(), "FreeD Tracking Data")	

  subtree:add(message_type,buffer(0,1)):set_text("Message Type : "..string.format("%02X", buffer(0,1):uint()))
  subtree:add(camera_id,buffer(1,1)):set_text("Camera ID : ".. buffer(1,1):uint().. "")

  subtree:add(pan,buffer(2,3)):set_text("Pan : ".. buffer(2,3):int()/-32768.0 .. "°")
  subtree:add(tilt,buffer(5,3)):set_text("Tilt : ".. buffer(5,3):int()/32768.0 .. "°")
  subtree:add(roll,buffer(8,3)):set_text("Roll : ".. buffer(8,3):int()/32768.0 .. "°")

  subtree:add(x,buffer(11,3)):set_text("X : ".. buffer(11,3):int()/64000.0 .. "m")
  subtree:add(y,buffer(14,3)):set_text("Y : ".. buffer(14,3):int()/64000.0 .. "m")
  subtree:add(height,buffer(17,3)):set_text("Height (Z) : ".. buffer(17,3):int()/64000.0 .. "m")
 
  subtree:add(zoom,buffer(20,3)):set_text("Zoom : ".. buffer(20,3):uint().. "")
  subtree:add(focus,buffer(23,3)):set_text("Focus : ".. buffer(23,3):uint().."")

  subtree:add(user,buffer(26,2)):set_text("User : 0x"..buffer(26,2):uint() .."") 

  -- The checksum is calculated by subtracting (modulo 256) each byte of the
  -- message, including the message type, from 40 (hex).
  local checksum_calc = 0x40
  for i=0,27 do
    checksum_calc = bit.band(checksum_calc - buffer(i,1):uint(), 0xFF)
  end

  local checksum_value = buffer(28,1):uint()
  local checksum_text = "Checksum " .. (checksum_calc == checksum_value and "OK" or "FAIL") .. " : 0x" .. string.format("%02X", checksum_value)
  subtree:add(checksum, buffer(28,1)):set_text(checksum_text)

end

freed_protocol:register_heuristic("udp", freed_protocol.dissector)