--
-- thoughtleader@internetofallthethings.com
--

cr3_proto = Proto("cr3","Crimson v3")

-- define the field names, widths, descriptions, and number base
-- looks like lua structs is what I should use here
local pf_payload_length = ProtoField.uint16("cr3.len", "Length", base.HEX)
local pf_reg = ProtoField.uint16("cr3.reg", "Register number", base.HEX)
local pf_payload = ProtoField.bytes("cr3.payload", "Payload")
local ptype = ProtoField.uint16("cr3.payload.type", "Type", base.HEX)
local pzero = ProtoField.uint16("cr3.payload.zero", "Zero", base.HEX)

local pdata = ProtoField.bytes("cr3.payload.data", "Data")
local pstring = ProtoField.string("cr3.payload.string", "String")

-- 0x1300
local p_1300_seq = ProtoField.uint16("cr3.payload.sequence", "Sequence", base.HEX)
local p_1300_subtype = ProtoField.uint16("cr3.payload.subtype", "Subtype", base.HEX)
local p_1300_value = ProtoField.uint32("cr3.payload.value", "Value", base.HEX)
local p_1700_value = p_1300_value

-- 0x1500
-- start 32bit
-- length
local p_1500_chunkstart = ProtoField.uint32("cr3.payload.chunkstart", "Chunk start", base.HEX)
local p_1500_chunklength = ProtoField.uint16("cr3.payload.chunklength", "Chunk Length", base.HEX)
local p_1500_chunkdata = ProtoField.bytes("cr3.payload.chunkdata", "Chunk Data")

-- 0x1b00
-- 32bit zero
-- 16bit readoffset
-- 16bit readlength
local p_1b00_zero = ProtoField.uint32("cr3.payload.zero", "Zero", base.HEX)
local p_1b00_readoffset = ProtoField.uint16("cr3.payload.readoffset", "Read offset", base.HEX)
local p_1b00_readlength = ProtoField.uint16("cr3.payload.readlength", "Read length", base.HEX)

-- example I followed said not to do the fields like this, risk of missing some
cr3_proto.fields = {
	pf_payload_length,
	pf_reg,
	pf_payload,
	ptype,
	pstring,
	pdata,
	p_1300_seq,
	p_1300_subtype,
	p_1300_value,
	p_1500_chunkstart,
	p_1500_chunklength,
	p_1500_chunkdata,
	p_1b00_zero,
	p_1b00_readoffset,
	p_1b00_readlength
}

-- trying out a global variable for processing any cr3 segments
local processing_segment = false
-- local reassembled_length = 0
-- local segment_cur = 0 
-- local segment_data = nil

function cr3_proto.dissector(tvbuf,pinfo,tree)

	-- length of the received packet
	local pktlen = tvbuf:reported_length_remaining()

	if not processing_segment then
		-- pf_payload_length
		local cr3len = tvbuf(0,2):uint()

		if pktlen == cr3len + 2 then
			dissect_cr3(tvbuf, pinfo, tree, cr3len)
			return
		elseif cr3len > pktlen then
			processing_segment = true
			pinfo.desegment_len = cr3len - pktlen + 2
			return
		else
			-- checking if this ever hits
			print "SHOULD NOT HIT THIS"
			return
		end
	else
		-- preumption is that setting desegment_len
		-- means we won't get called until we recv that much
		dissect_cr3(tvbuf, pinfo, tree, cr3len)
		processing_segment = false
		return
	end
		
end

function dissect_cr3(tvbuf,pinfo,tree,cr3len)

	-- set the protocol column based on the Proto object
	pinfo.cols.protocol = cr3_proto.description
	
	-- length of the entire CR3 payload
	local pktlen = tvbuf:reported_length_remaining()
	
	-- define this entire length as the object of dissection
	local subtree = tree:add(cr3_proto, tvbuf:range(0, pktlen))
		
	-- setup fields in the proper order and width
	local offset = 0
		
	local cr3len = tvbuf(offset,2):uint()
	subtree:add(pf_payload_length,tvbuf(offset,2))
	offset = offset + 2
		
	local reg = tvbuf(offset,2):uint()
	subtree:add(pf_reg, reg)
	offset = offset + 2
	
	-- payload gets broken out
	local payloadtree = subtree:add(pf_payload, tvbuf:range(offset, pktlen - offset))
	payloadtree:append_text(string.format(" (0x%02x bytes)", tvbuf:reported_length_remaining() - 4))
	
	payloadtree:add(ptype, tvbuf(offset, 2))
	local packettype = tvbuf:range(offset, 2):uint()
	offset = offset + 2

	-- setting CR3 summary data into the info column in the UI
	pinfo.cols.info = string.format("Register: 0x%04x, Type: 0x%04x, Bytes: 0x%04x", reg, packettype, cr3len + 2)

	print(string.format("packettype 0x%04x",packettype))


	-- type-specific handling here
	-- packettype 0x0100
	if packettype == 0x0100 then
		-- no data
		return
	elseif packettype == 0x0200 then
		-- no data
		return
	elseif packettype == 0x0300 then
	
		if (reg == 0x012a or reg == 0x012b) then
			string = tvbuf:range(offset):stringz()
			payloadtree:add(pstring, string)
		else
			local data = tvbuf:range(offset)
			payloadtree:add(pdata,data)
		end

		return
	elseif packettype == 0x1000 or packettype == 0x1600 then
		-- 16 byte read
		if not crlen == 0x14 then
			print "subtype 0x1000, length violates assumption"
			return
		end

		local data = tvbuf:range(offset)
		payloadtree:add(pdata,data)

		return
	elseif packettype == 0x1100 then
		if not(cr3len > 4) then
			print(string.format("subtype 0x%04x, length violates assumption", packettype))
			return
		end

		local data = tvbuf:range(offset)
		payloadtree:add(pdata, data)

		return
	elseif packettype == 0x1300 or packettype == 0x1400 then
		-- sequence
		-- type 
		-- value
		if not (cr3len == 0x0c) then
			print(string.format("subtype 0x%04x, length violates assumption", packettype))
			return
		end

		local seq = tvbuf(offset,2):uint()
		offset = offset + 2
		local subtype = tvbuf(offset,2):uint()
		offset = offset + 2
		local value = tvbuf(offset,4):uint()
		offset = offset + 4

		payloadtree:add(p_1300_seq,seq)
		payloadtree:add(p_1300_subtype,subtype)
		payloadtree:add(p_1300_value,value)
		
		return
	elseif packettype == 0x1200 or packettype == 0x1202 or packettype == 0x1500 then

		if not(cr3len > 4) then
			print(string.format("subtype 0x%04x, length violates assumption", packettype))
			return
		end

		-- start
		-- length

		local chunkstart = tvbuf(offset,4):uint()
		offset = offset + 4
		local chunklength = tvbuf(offset,2):uint()
		offset = offset + 2
		local chunkdata = tvbuf(offset)

		payloadtree:add(p_1500_chunkstart, chunkstart)
		payloadtree:add(p_1500_chunklength, chunklength)
		payloadtree:add(p_1500_chunkdata, chunkdata)

		return
	elseif packettype == 0x1700 then
		-- seems to always read 0x7530 (30000)
		local value = tvbuf(offset,4):uint()
		payloadtree:add(p_1700_value, value)

		return
	elseif packettype == 0x1800 then
		-- no read
		return
	elseif packettype == 0x1a00 then

		if cr3len > 4 then
			local data = tvbuf:range(offset)
			payloadtree:add(pdata, data)
		end

		return
	elseif packettype == 0x1b00 then
		if cr3len < 0x0c then
			print(string.format("subtype 0x%04x, length violates assumption", packettype))
			return
		end
		
		local zero = tvbuf(offset,4):uint() 
		offset = offset + 4
		local readoffset = tvbuf(offset,2):uint() 
		offset = offset + 2
		local readlength = tvbuf(offset,2):uint() 
		offset = offset + 2
		
		payloadtree:add(p_1b00_zero, zero)
		payloadtree:add(p_1b00_readoffset, readoffset)
		payloadtree:add(p_1b00_readlength, readlength)

		return
	elseif packettype == 0x1c00 then
		-- no read
		return
	elseif packettype == 0x1e00 then
		-- one byte
		local data = tvbuf:range(offset)
		payloadtree:add(pdata, data)
		return
	elseif packettype == 0x1f00 then
		-- no read
		return
	elseif packettype == 0x2e00 then
		-- no read
		return
	else
		print(string.format("Unknown packettype 0x%04x", packettype))
		return
	end

	return
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol tcp:789
tcp_table:add(789,cr3_proto)
