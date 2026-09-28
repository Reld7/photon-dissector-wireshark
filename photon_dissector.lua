local photon = Proto("photon", "Photon Protocol")

-- Command types
local cmd_types = {
    [0x01] = "Ack",
    [0x02] = "Connect",
    [0x03] = "VerifyConnect",
    [0x04] = "Disconnect",
    [0x05] = "Ping",
    [0x06] = "SendReliable",
    [0x07] = "SendUnreliable",
    [0x08] = "Fragment",
    [0x11] = "Ack",
}

-- Reliable types
local reliable_types = {
    [0x02] = "OperationRequest",
    [0x03] = "OtherOperationResponse",
    [0x04] = "EventDataType",
    [0x06] = "ExchangeKeys",
    [0x07] = "OperationResponse",
}

-- Port roles
local port_roles = {
    [27000] = "NameServer",
    [27001] = "MasterServer",
    [27002] = "GameServer",
    [5055]  = "MasterServer",
    [5056]  = "GameServer",
    [5058]  = "NameServer",
}

-- Region rules
local region_rules = {
    { name = "[USA East]",     ips = { "5.8.93.16" },      prefixes = { "188.241.71." } },
    { name = "[USA West]",     ips = { "37.9.33.138" },    prefixes = { "86.105.169." } },
    { name = "[EU Amsterdam]", ips = { "85.234.65.254" },  prefixes = { "80.93.214." } },
    { name = "[Japan Tokyo]",  ips = { "87.120.204.208" }, prefixes = { "82.117.224." } },
}

-- Protocol fields

-- Header
local f_peer_id       = ProtoField.uint16 ( "photon.peer_id",       "Peer ID",        base.HEX)
local f_crc           = ProtoField.uint8  ( "photon.crc",           "CRC",            base.DEC)
local f_cmdcount      = ProtoField.uint8  ( "photon.cmd_count",     "Command Count",  base.DEC)
local f_timestamp     = ProtoField.uint32 ( "photon.timestamp",     "Timestamp",      base.DEC)
local f_challenge     = ProtoField.uint32 ( "photon.challenge",     "Challenge",      base.HEX)

-- Command
local f_cmd_type      = ProtoField.uint8  ( "photon.cmd.type",      "Cmd Type",       base.HEX, cmd_types)
local f_cmd_chan      = ProtoField.uint8  ( "photon.cmd.chan",      "Channel",        base.DEC)
local f_cmd_flags     = ProtoField.uint8  ( "photon.cmd.flags",     "Flags",          base.HEX)
local f_cmd_len       = ProtoField.uint32 ( "photon.cmd.len",       "Length",         base.DEC)
local f_cmd_seq       = ProtoField.uint32 ( "photon.cmd.seq",       "Rel Seq",        base.DEC)

-- Reliable payload
local f_rel_type      = ProtoField.uint8  ( "photon.rel.type",      "Reliable Type",  base.HEX, reliable_types)
local f_payload       = ProtoField.bytes  ( "photon.payload",       "Payload Data")

-- Host / region
local f_host_name     = ProtoField.string ( "photon.host",          "Target Host")
local f_region        = ProtoField.string ( "photon.region",        "Server Region")
local f_port_role     = ProtoField.string ( "photon.port_role",     "Port Role")

-- Session heuristics
local f_session_kb    = ProtoField.float  ( "photon.session_kb",    "Session Data (KB)")
local f_unanswered    = ProtoField.uint32 ( "photon.unanswered",    "Unanswered Count")

-- ACK payload (0x01 / 0x11)
local f_ack_rcv_seq   = ProtoField.uint32 ( "photon.ack.recv_seq",  "Acked Rel Seq",  base.DEC)
local f_ack_rcv_time  = ProtoField.uint32 ( "photon.ack.recv_time", "Recv Send Time", base.DEC)

-- Connect / Verifyconnect payload
local f_conn_mtu      = ProtoField.uint16 ( "photon.conn.mtu",       "MTU",              base.DEC)
local f_conn_window   = ProtoField.uint32 ( "photon.conn.window",    "Window Size",      base.DEC)
local f_conn_channels = ProtoField.uint8  ( "photon.conn.channels",  "Channel Count",    base.DEC)
local f_conn_peer_id  = ProtoField.uint16 ( "photon.conn.peer_id",   "Assigned Peer ID", base.HEX)

-- Fragment header
local f_frag_start    = ProtoField.uint32 ( "photon.frag.start_seq",  "Start Seq",       base.DEC)
local f_frag_count    = ProtoField.uint32 ( "photon.frag.count",      "Fragment Count",  base.DEC)
local f_frag_num      = ProtoField.uint32 ( "photon.frag.number",     "Fragment #",      base.DEC)
local f_frag_total    = ProtoField.uint32 ( "photon.frag.total_len",  "Total Length",    base.DEC)
local f_frag_offset   = ProtoField.uint32 ( "photon.frag.offset",     "Fragment Offset", base.DEC)

-- HTTP tunnel params
local f_http_host     = ProtoField.string ( "photon.http.host",      "HTTP Host")
local f_http_app_id   = ProtoField.string ( "photon.http.app_id",    "App ID")
local f_http_version  = ProtoField.string ( "photon.http.version",   "Client Version")
local f_http_proto    = ProtoField.string ( "photon.http.protocol",  "Protocol")
local f_http_sid      = ProtoField.string ( "photon.http.sid",       "SID")
local f_http_clen     = ProtoField.uint32 ( "photon.http.clen",      "Content-Length", base.DEC)

-- Ping
local f_ping_echo     = ProtoField.uint8  ( "photon.ping.echo",      "Echo Byte", base.HEX)

-- Encrypted packet (7 byte header + IV + CT + Tag)
local f_enc_iv        = ProtoField.bytes  ( "photon.enc.iv",          "IV (Nonce)")
local f_enc_ct        = ProtoField.bytes  ( "photon.enc.ct",          "Ciphertext")
local f_enc_tag       = ProtoField.bytes  ( "photon.enc.tag",         "Auth Tag (16 bytes)")
local f_enc_ct_len    = ProtoField.uint32 ( "photon.enc.ct_len",      "Ciphertext Length", base.DEC)
local f_enc_plaintext_hdr = ProtoField.bytes( "photon.enc.plain_hdr", "Plaintext Header (7 bytes)")

photon.fields = {
    f_peer_id, f_crc, f_cmdcount, f_timestamp, f_challenge,
    f_cmd_type, f_cmd_chan, f_cmd_flags, f_cmd_len, f_cmd_seq,
    f_rel_type, f_payload,
    f_host_name, f_region, f_port_role,
    f_session_kb, f_unanswered,
    f_ack_rcv_seq, f_ack_rcv_time,
    f_conn_mtu, f_conn_window, f_conn_channels, f_conn_peer_id,
    f_frag_start, f_frag_count, f_frag_num, f_frag_total, f_frag_offset,
    f_http_host, f_http_app_id, f_http_version, f_http_proto, f_http_sid, f_http_clen,
    f_ping_echo,
    f_enc_iv, f_enc_ct, f_enc_tag, f_enc_ct_len, f_enc_plaintext_hdr,
}

-- Helpers

local sessions = {}

local function can_read(tvb, offset, n)
    return (offset + n) <= tvb:len()
end

-- Region detection by ip
local function detect_region(ip_src, ip_dst)
    local function check_ip(ip)
        for _, rule in ipairs(region_rules) do
            for _, exact_ip in ipairs(rule.ips) do
                if ip == exact_ip then return rule.name end
            end
            for _, prefix in ipairs(rule.prefixes) do
                if ip:match("^" .. prefix:gsub("%.", "%%.") .. "") then return rule.name end
            end
        end
        return nil
    end
    return check_ip(ip_src) or check_ip(ip_dst)
end

local function get_port_role(src_port, dst_port)
    return port_roles[src_port] or port_roles[dst_port] or ""
end

-- Parse http post
local function parse_http_params(raw_str)
    local params = {}
    local url = raw_str:match("POST%s+(%S+)%s+HTTP")
    if url then
        params.app_id  = url:match("[?&]app=([%w%-]+)")
        params.version = url:match("[?&]clientversion=([%w%.]+)")
        params.proto   = url:match("[?&]protocol=([%w]+)")
        params.sid     = url:match("[?&]sid=([%d]+)")
    end
    params.host = raw_str:match("Host:%s*([%w%.%-]+:%d+)")
    local cl = raw_str:match("Content%-Length:%s*(%d+)")
    params.clen = cl and tonumber(cl) or nil
    return params
end

-- Dissector

function photon.dissector(tvb, pinfo, tree)
    local pkt_len  = tvb:len()
    local s_port   = pinfo.src_port
    local d_port   = pinfo.dst_port
    local ip_src   = tostring(pinfo.src)
    local ip_dst   = tostring(pinfo.dst)

    -- Bidirectional session key
    local session_key = (ip_src < ip_dst)
        and (ip_src..":"..s_port.."-"..ip_dst..":"..d_port)
        or  (ip_dst..":"..d_port.."-"..ip_src..":"..s_port)

    if not sessions[session_key] then
        sessions[session_key] = { bytes = 0, last_sender = nil, unanswered = 0 }
    end
    local sess = sessions[session_key]

    -- Update stats
    if not pinfo.visited then
        sess.bytes = sess.bytes + pkt_len
        if sess.last_sender == ip_src then
            sess.unanswered = sess.unanswered + 1
        else
            sess.unanswered = 0
            sess.last_sender = ip_src
        end
    end

    local kb_total   = sess.bytes / 1024
    local region_tag = detect_region(ip_src, ip_dst) or ""
    local role_tag   = get_port_role(s_port, d_port)
    pinfo.cols.protocol = "PHOTON"

    -- Block detection heuristic
    local block_alert = ""
    if sess.unanswered >= 15 and kb_total >= 14.0 and kb_total <= 30.0 then
        block_alert = string.format("[16BLOCK: %.1fKB][%dpkts] ", kb_total, sess.unanswered)
    end

    -- Keep-Alive Ping (12 x 0x7D + 1 echo byte)
    if pkt_len >= 4 and tvb(0,4):uint() == 0x7d7d7d7d then
        local root = tree:add(photon, tvb(), "Photon Keep-Alive Ping")
        root:add(f_payload, tvb(0, math.min(12, pkt_len))):set_text("Keep-Alive pattern (12 x 0x7D)")
        if pkt_len >= 13 then
            root:add(f_ping_echo, tvb(12, 1))
        end
        if region_tag ~= "" then root:add(f_region, region_tag) end
        if role_tag   ~= "" then root:add(f_port_role, role_tag) end
        pinfo.cols.info = block_alert .. "Keep-Alive Ping " .. region_tag
        return
    end

    -- Protected Payload (AES-GCM)
    local crc_val = pkt_len >= 3 and tvb(2, 1):uint() or 0
    if crc_val == 1 and pkt_len >= 7 + 12 + 16 then
        local root = tree:add(photon, tvb(), "Photon Data [Protected Payload]")
        root:add(f_session_kb, kb_total)
        root:add(f_unanswered, sess.unanswered)
        if region_tag ~= "" then root:add(f_region, region_tag) end
        if role_tag   ~= "" then root:add(f_port_role, role_tag) end

        local plain_hdr = root:add(photon, tvb(0, 7), "Plaintext Header (7 bytes)")
        plain_hdr:add(f_enc_plaintext_hdr, tvb(0, 7))
        local peer_id_val = tvb(0,2):uint()
        local peer_id_item = plain_hdr:add(f_peer_id, tvb(0,2))
        if peer_id_val == 0xFFFF then
            peer_id_item:append_text("  [Initial Connect]")
        end
        plain_hdr:add(f_crc, tvb(2,1)):append_text("  (protection flag)")
        plain_hdr:add(f_challenge, tvb(3,4))

        root:add(f_enc_iv, tvb(7, 12)):append_text("  [AES-GCM Nonce]")

        local ct_len = pkt_len - 7 - 12 - 16
        if ct_len > 0 then
            local ct_item = root:add(f_enc_ct, tvb(19, ct_len))
            ct_item:append_text(string.format("  [%d bytes encrypted data]", ct_len))
            root:add(f_enc_ct_len, ct_len)
        end

        root:add(f_enc_tag, tvb(19 + ct_len, 16)):append_text("  [AES-GCM Auth Tag]")
        pinfo.cols.info = block_alert .. "[" .. role_tag .. "] (Protected Payload) " .. region_tag
        return
    end

    -- Standard Photon header (12 bytes)
    if pkt_len < 12 then
        pinfo.cols.info = block_alert .. "Short Packet " .. region_tag
        return
    end

    local root = tree:add(photon, tvb(), "Photon Data")
    root:add(f_session_kb, kb_total)
    root:add(f_unanswered, sess.unanswered)
    if region_tag ~= "" then root:add(f_region, region_tag) end
    if role_tag   ~= "" then root:add(f_port_role, role_tag) end

    local peer_id_val  = tvb(0,2):uint()
    local peer_id_item = root:add(f_peer_id, tvb(0,2))
    if peer_id_val == 0xFFFF then
        peer_id_item:append_text("  [Initial Connect]")
    end
    root:add(f_crc, tvb(2,1))
    local cmd_count = tvb(3,1):uint()
    root:add(f_cmdcount, tvb(3,1))
    root:add(f_timestamp, tvb(4,4))
    root:add(f_challenge, tvb(8,4))

    if cmd_count == 0 or cmd_count > 100 then
        root:add(f_payload, tvb(12)):set_text("Fully Encrypted / Obfuscated Data (heuristic)")
        pinfo.cols.info = block_alert .. "[ENCRYPTED] " .. role_tag .. " " .. region_tag
        return
    elseif (12 + cmd_count * 12) > pkt_len then
        root:add(f_payload, tvb(12)):set_text("Fully Encrypted (header mismatch)")
        pinfo.cols.info = block_alert .. "[ENCRYPTED] " .. role_tag .. " " .. region_tag
        return
    end

    -- Command parsing
    local offset         = 12
    local cmd_list       = {}
    local detected_host  = nil

    for i = 1, cmd_count do
        if not can_read(tvb, offset, 12) then break end
        local c_type  = tvb(offset,   1):uint()
        local c_chan  = tvb(offset+1, 1):uint()
        local c_flags = tvb(offset+2, 1):uint()
        local c_len   = tvb(offset+4, 4):uint()
        local c_seq   = tvb(offset+8, 4):uint()
        local c_name  = cmd_types[c_type] or "Unknown"

        local is_reliable = (c_flags % 2 == 1)
        table.insert(cmd_list, c_name)

        local safe_c_len = math.min(c_len, pkt_len - offset)
        if safe_c_len < 12 then break end

        local cmd_tree = root:add(photon, tvb(offset, safe_c_len), "Cmd: " .. c_name)
        cmd_tree:add(f_cmd_type, tvb(offset, 1))
        cmd_tree:add(f_cmd_chan, tvb(offset+1, 1))
        local flags_item = cmd_tree:add(f_cmd_flags, tvb(offset+2, 1))
        if is_reliable then
            flags_item:append_text("  (Reliable)")
        else
            flags_item:append_text("  (Unreliable)")
        end
        cmd_tree:add(f_cmd_len, tvb(offset+4, 4))
        cmd_tree:add(f_cmd_seq, tvb(offset+8, 4))

        local payload_offset = offset + 12
        local payload_len    = (c_len > 12) and (c_len - 12) or 0

        -- 0x01 / 0x11 Acknowledge
        if (c_type == 0x01 or c_type == 0x11) and payload_len >= 8 and can_read(tvb, payload_offset, 8) then
            cmd_tree:add(f_ack_rcv_seq, tvb(payload_offset, 4))
            cmd_tree:add(f_ack_rcv_time, tvb(payload_offset+4, 4))

        -- 0x02 Connect
        elseif c_type == 0x02 and payload_len >= 8 and can_read(tvb, payload_offset, payload_len) then
            if payload_len >= 4 then cmd_tree:add(f_conn_mtu, tvb(payload_offset+2, 2)) end
            if payload_len >= 8 then cmd_tree:add(f_conn_window, tvb(payload_offset+4, 4)) end

        -- 0x03 Verifyconnect
        elseif c_type == 0x03 and payload_len >= 4 and can_read(tvb, payload_offset, payload_len) then
            cmd_tree:add(f_conn_peer_id, tvb(payload_offset, 2))
            if payload_len >= 4 then cmd_tree:add(f_conn_mtu, tvb(payload_offset+2, 2)) end
            if payload_len >= 8 then cmd_tree:add(f_conn_window, tvb(payload_offset+4, 4)) end

        -- 0x05 Ping
        elseif c_type == 0x05 then
            cmd_tree:append_text("  [keep-alive]")

        -- 0x08 Fragment
        elseif c_type == 0x08 and payload_len >= 20 and can_read(tvb, payload_offset, 20) then
            local fh = cmd_tree:add(photon, tvb(payload_offset, 20), "Fragment Header")
            fh:add(f_frag_start, tvb(payload_offset, 4))
            fh:add(f_frag_count, tvb(payload_offset+4, 4))
            fh:add(f_frag_num, tvb(payload_offset+8, 4))
            fh:add(f_frag_total, tvb(payload_offset+12, 4))
            fh:add(f_frag_offset, tvb(payload_offset+16, 4))
            local frag_num   = tvb(payload_offset+8, 4):uint()
            local frag_total = tvb(payload_offset+12, 4):uint()
            fh:append_text(string.format(
                "  [frag %d of %d, total %d B / %.1f KB]",
                frag_num,
                tvb(payload_offset+4, 4):uint(),
                frag_total,
                frag_total / 1024
            ))

            local fdata_off = payload_offset + 20
            local fdata_len = safe_c_len - 12 - 20
            if fdata_len > 0 and can_read(tvb, fdata_off, fdata_len) then
                local fdata_tvb = tvb(fdata_off, fdata_len)
                cmd_tree:add(f_payload, fdata_tvb)

                -- Fragment #0: parse http header
                if frag_num == 0 then
                    local raw = fdata_tvb:raw()
                    if raw:sub(1,4) == "POST" then
                        local hp = parse_http_params(raw)
                        local http_tree = cmd_tree:add(photon, fdata_tvb, "HTTP Tunnel")
                        if hp.host    then
                            http_tree:add(f_http_host, hp.host)
                            detected_host = hp.host
                        end
                        if hp.app_id  then http_tree:add(f_http_app_id, hp.app_id) end
                        if hp.version then http_tree:add(f_http_version, hp.version) end
                        if hp.proto   then http_tree:add(f_http_proto, hp.proto) end
                        if hp.sid     then http_tree:add(f_http_sid, hp.sid) end
                        if hp.clen    then http_tree:add(f_http_clen, hp.clen) end
                    end
                end
            end

        -- 0x06 / 0x07 Sendreliable / Sendunreliable
        elseif payload_len > 0 and can_read(tvb, payload_offset, payload_len) then
            local p_tvb = tvb(payload_offset, payload_len)
            cmd_tree:add(f_payload, p_tvb)
            if c_type == 0x06 and payload_len >= 2 then
                cmd_tree:add(f_rel_type, tvb(payload_offset, 1))
            end

            -- Search host in payload
            local p_str = p_tvb:raw()
            local host_match = p_str:match("Host:%s*([%w%.%-]+:%d+)")
            if host_match then
                cmd_tree:add(f_host_name, host_match)
                detected_host = host_match
            end
        end

        offset = offset + c_len
        if offset >= pkt_len then break end
    end

    -- Info column
    local info_str = block_alert
        .. (role_tag ~= "" and "["..role_tag.."] " or "")
        .. "Cmds: " .. cmd_count
        .. " (" .. table.concat(cmd_list, ", ") .. ")"
    if detected_host then
        info_str = info_str .. " [Host: " .. detected_host .. "]"
    end
    pinfo.cols.info = info_str .. " " .. region_tag
end

-- Register protocol
local udp_table    = DissectorTable.get("udp.port")
local target_ports = {27000, 27001, 27002, 5055, 5056, 5058}
for _, port in ipairs(target_ports) do
    udp_table:add(port, photon)
end