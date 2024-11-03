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

-- FreeD wireshark disector 
-- Will read the raw data from rotation and location in degrees and meters, zoom and focus fields are just the raw vales, Iris in F stop and timestamp
-- Does not support additional data being sent in the freeD packet


local freed_protocol = Proto("FreeD","FreeD protocol")

local pos_x = ProtoField.int32("freed.pos_x","position X",base.DEC)
local pos_y = ProtoField.int32("freed.pos_y","position Y",base.DEC)
local pos_z = ProtoField.int32("freed.pos_z","position Z",base.DEC)

local rotation_x = ProtoField.int32("freed.rotation_x","rotation X",base.DEC)
local rotation_y = ProtoField.int32("freed.rotation_y","rotation Y",base.DEC)
local rotation_z = ProtoField.int32("freed.rotation_z","rotation Z",base.DEC)

local zoom = ProtoField.int32("freed.zoom","Zoom",base.DEC)
local focus = ProtoField.int32("freed.focus","Focus",base.DEC)
local camera_id = ProtoField.int32("freed.camera_id","Camera ID",base.DEC)

local iris = ProtoField.uint32("freed.iris","Iris",base.DEC)
local timestamp = ProtoField.uint32("freed.timestamp","Timestamp",base.DEC)

freed_protocol.fields = {pos_x, pos_y,pos_z,rotation_x,rotation_y,rotation_z,zoom,focus,camera_id,iris,timestamp}

function freed_protocol.dissector(buffer, pinfo, tree)
  -- Check if UDP payload could be a D1 packet
  if buffer:len() ~= 29 then return end
  if buffer(0,1):uint() ~= 0xD1 then return end
  
  pinfo.cols.protocol = freed_protocol.name
  
  local subtree = tree:add(freed_protocol, buffer(), "FreeD Tracking Data")	
  
  subtree:add(pos_x,buffer(11,3)):set_text("Position X : ".. buffer(11,3):int()/64000.0 .. "m")
  subtree:add(pos_y,buffer(17,3)):set_text("Position Y : ".. buffer(17,3):int()/64000.0 .. "m")
  subtree:add(pos_z,buffer(14,3)):set_text("Position Z : ".. buffer(20,3):int()/64000.0 .. "m")
  
  subtree:add(rotation_x,buffer(5,3)):set_text("Rotation X : ".. buffer(5,3):int()/32768.0 .. "°")
  subtree:add(rotation_y,buffer(2,3)):set_text("Rotation Y : ".. buffer(2,3):int()/-32768.0 .. "°")
  subtree:add(rotation_z,buffer(8,3)):set_text("Rotation Z : ".. buffer(8,3):int()/32768.0 .. "°")
 
  subtree:add(zoom,buffer(20,3)):set_text("Zoom : ".. buffer(20,3):uint().. "")
  subtree:add(focus,buffer(23,3)):set_text("Focus : ".. buffer(20,3):uint().."")
  subtree:add(camera_id,buffer(1,1))

  subtree:add(iris,buffer(26,2)):set_text("Iris : f"..buffer(26,2):uint()/100 .."") 
  subtree:add(timestamp,buffer(28,1)):set_text("Timestamp : "..buffer(28,1):uint().. "")
end

freed_protocol:register_heuristic("udp", freed_protocol.dissector)