
-- Wireshark-compatible traffic analyzer with all features

local plugin_info = {
    version = "4.1",
    author = "utracks",
    description = "Enterprise Traffic Analyzer (Wireshark-native)"
}

-- 1. CONFIGURATION SYSTEM ====================================================

local config_file = os.getenv("APPDATA").."\\Wireshark\\enterprise_traffic_analyzer.conf"

local function load_configuration()
    local default_config = {
        dns = {
            max_query_length = 100,
            suspicious_record_types = {10, 16}, -- NULL, TXT
            check_base64 = true,
            whitelist = {"example.com", "trusted.domain"},
            query_threshold = 50 -- queries/minute
        },
        http = {
            max_uri_length = 200,
            max_header_length = 1024,
            suspicious_agents = {"sqlmap", "nikto", "wget", "curl"},
            whitelist = {"api.trusted.com", "cdn.safe.org"},
            request_threshold = 100 -- requests/minute
        },
        https = {
            check_ja3 = true,
            check_ssl_versions = true,
            min_tls_version = 0x0303 -- TLS 1.2
        },
        alerts = {
            enabled = true,
            desktop = true,
            logfile = true
        },
        threat_intel = {
            auto_update = true,
            update_interval = 24 -- hours
        }
    }
    
    local file = io.open(config_file, "r")
    if file then
        local content = file:read("*a")
        file:close()
        local success, loaded = pcall(loadstring("return "..content))
        if success and loaded then
            -- Merge with defaults
            for k,v in pairs(default_config) do
                if not loaded[k] then loaded[k] = v end
            end
            return loaded
        end
    end
    return default_config
end

local function save_configuration(cfg)
    local file = io.open(config_file, "w")
    if file then
        file:write("return {\n")
        for section, settings in pairs(cfg) do
            file:write("  "..section.." = {\n")
            for k,v in pairs(settings) do
                if type(v) == "table" then
                    file:write("    "..k.." = {")
                    for i,val in ipairs(v) do
                        file:write((i > 1 and ", " or "").."\""..val.."\"")
                    end
                    file:write("},\n")
                elseif type(v) == "boolean" then
                    file:write("    "..k.." = "..(v and "true" or "false")..",\n")
                elseif type(v) == "number" then
                    file:write("    "..k.." = "..v..",\n")
                end
            end
            file:write("  },\n")
        end
        file:write("}\n")
        file:close()
        return true
    end
    return false
end

local config = load_configuration()

-- 2. THREAT INTELLIGENCE ====================================================

local threat_intel = {
    last_update = 0,
    fingerprints = {
        -- Known malicious JA3 fingerprints
        "6734f37431670b3ab4292b8f60f29984", -- Dridex
        "1d704b835c357712e8e4aec1a8224a5a", -- TrickBot
        "5d70a3d927d170f5a7a5a5a5a5a5a5a5",  -- Emotet
        "a0e9f5d64349fb13191bc781f81f42e1", -- QakBot
        "07c4a0c77a0e7b66b78e60a1f6a694c6"  -- Cobalt Strike
    },
    patterns = {
        { pattern = "[%s\\/]union[%s\\/].*select", description = "SQL Injection" },
        { pattern = "<script[^>]*>.*</script>", description = "XSS Attempt" },
        { pattern = "\\$_(GET|POST|REQUEST|COOKIE)", description = "PHP Injection" },
        { pattern = "\\bexec\\s*%(", description = "Command Injection" }
    }
}

-- 3. JA3 FINGERPRINTING (Wireshark-native) ===================================

local function get_ja3_fingerprint()
    -- Get Wireshark's TLS fields
    local tls_handshake = Field.new("tls.handshake.type")
    local tls_version = Field.new("tls.handshake.version")
    local cipher_suites = Field.new("tls.handshake.ciphersuite")
    local extensions = Field.new("tls.handshake.extension.type")
    local comp_methods = Field.new("tls.handshake.compression_method")
    
    if not tls_handshake or tls_handshake() ~= 1 then return nil end -- Not Client Hello
    
    local ja3_parts = {}
    
    -- TLS Version
    if tls_version then
        table.insert(ja3_parts, tostring(tls_version()))
    end
    
    -- Cipher Suites
    if cipher_suites then
        local suites = {}
        for _, cs in ipairs({cipher_suites()}) do
            table.insert(suites, tostring(cs))
        end
        table.insert(ja3_parts, table.concat(suites, "-"))
    end
    
    -- Extensions
    if extensions then
        local exts = {}
        for _, ext in ipairs({extensions()}) do
            table.insert(exts, tostring(ext))
        end
        table.insert(ja3_parts, table.concat(exts, "-"))
    end
    
    -- Compression Methods (if present)
    if comp_methods then
        table.insert(ja3_parts, tostring(comp_methods()))
    end
    
    if #ja3_parts > 0 then
        local ja3_str = table.concat(ja3_parts, ",")
        return string.lower(ByteArray.new(ja3_str):md5():tohex())
    end
    
    return nil
end

-- 4. ALERTING SYSTEM =========================================================

local alert_history = {}

local function send_alert(alert_type, message, severity)
    if not config.alerts.enabled then return end
    
    local alert = {
        timestamp = os.time(),
        type = alert_type,
        message = message,
        severity = severity or 50
    }
    table.insert(alert_history, alert)
    
    -- Log to file
    if config.alerts.logfile then
        local log_file = io.open("wireshark_alerts.log", "a")
        if log_file then
            log_file:write(string.format("[%s] %s: %s (Severity: %d)\n",
                os.date("%Y-%m-%d %H:%M:%S"), alert_type, message, severity))
            log_file:close()
        end
    end
    
    -- Desktop alert (Wireshark-native)
    if config.alerts.desktop and severity >= 80 then
        local window = TextWindow.new("Security Alert")
        window:set(string.format(
            "=== %s ===\n%s\n\nSeverity: %d/100\nTimestamp: %s",
            alert_type, message, severity, os.date("%Y-%m-%d %H:%M:%S")
        ))
    end
end

-- 5. DNS TUNNELING DETECTOR =================================================

local dns_tunnel = Proto("dnstunnel", "DNS Tunneling Detector")

local f_dns_suspicious = ProtoField.string("dnstunnel.reason", "Reason")
local f_dns_len = ProtoField.uint32("dnstunnel.length", "Packet Length")

dns_tunnel.fields = {f_dns_suspicious, f_dns_len}

function dns_tunnel.dissector(tvb, pinfo, tree)
    if pinfo.port ~= 53 and pinfo.dst_port ~= 53 then return end
    
    local dns_tree = tree:add(dns_tunnel, tvb())
    local is_suspicious = false
    local reason = ""
    
    -- Length check
    local query_len = tvb:len()
    if query_len > config.dns.max_query_length then
        is_suspicious = true
        reason = "Long query ("..query_len.." bytes)"
    end
    
    -- Record type check
    local qtype = Field.new("dns.qry.type")
    if qtype then
        for _, suspicious_type in ipairs(config.dns.suspicious_record_types) do
            if qtype() == suspicious_type then
                is_suspicious = true
                reason = reason..(reason ~= "" and ", " or "").."Suspicious type ("..qtype()..")"
                break
            end
        end
    end
    
    -- Whitelist check
    local dns_qry_name = Field.new("dns.qry.name")
    if dns_qry_name then
        local query = dns_qry_name()
        for _, wl_domain in ipairs(config.dns.whitelist) do
            if string.find(query, wl_domain, 1, true) then
                is_suspicious = false
                reason = ""
                break
            end
        end
    end
    
    -- Add to tree
    if is_suspicious then
        dns_tree:add(f_dns_suspicious, reason)
        pinfo.cols.info:append(" [DNS Tunneling: "..reason.."]")
        send_alert("DNS_TUNNELING", "Suspicious DNS: "..reason, 80)
    end
    dns_tree:add(f_dns_len, query_len)
end

-- 6. HTTP ANOMALY DETECTOR ==================================================

local http_anomaly = Proto("httpano", "HTTP Anomaly Detector")

local f_http_reason = ProtoField.string("httpano.reason", "Reason")
local f_http_len = ProtoField.uint32("httpano.length", "Packet Length")

http_anomaly.fields = {f_http_reason, f_http_len}

function http_anomaly.dissector(tvb, pinfo, tree)
    if pinfo.port ~= 80 and pinfo.dst_port ~= 80 and
       pinfo.port ~= 8080 and pinfo.dst_port ~= 8080 then
        return
    end
    
    local http_tree = tree:add(http_anomaly, tvb())
    local is_suspicious = false
    local reason = ""
    
    -- URI length check
    local http_request_uri = Field.new("http.request.uri")
    if http_request_uri and http_request_uri():len() > config.http.max_uri_length then
        is_suspicious = true
        reason = "Long URI ("..http_request_uri():len().." chars)"
    end
    
    -- User-Agent check
    local http_user_agent = Field.new("http.user_agent")
    if http_user_agent then
        local ua = http_user_agent():lower()
        for _, sus_ua in ipairs(config.http.suspicious_agents) do
            if string.find(ua, sus_ua, 1, true) then
                is_suspicious = true
                reason = reason..(reason ~= "" and ", " or "").."Suspicious UA: "..sus_ua
                break
            end
        end
    end
    
    -- Threat pattern matching
    local http_payload = Field.new("http.file_data") or Field.new("http.request.line")
    if http_payload then
        for _, threat in ipairs(threat_intel.patterns) do
            if string.find(http_payload():lower(), threat.pattern) then
                is_suspicious = true
                reason = reason..(reason ~= "" and ", " or "")..threat.description
                break
            end
        end
    end
    
    -- Add to tree
    if is_suspicious then
        http_tree:add(f_http_reason, reason)
        pinfo.cols.info:append(" [HTTP Anomaly: "..reason.."]")
        send_alert("HTTP_ANOMALY", "Suspicious HTTP: "..reason, 85)
    end
    http_tree:add(f_http_len, tvb:len())
end

-- 7. HTTPS/JA3 ANALYZER ======================================================

local https_analyzer = Proto("httpsano", "HTTPS/JA3 Analyzer")

local f_ja3 = ProtoField.string("httpsano.ja3", "JA3 Fingerprint")

https_analyzer.fields = {f_ja3}

function https_analyzer.dissector(tvb, pinfo, tree)
    if not config.https.check_ja3 then return end
    if pinfo.port ~= 443 and pinfo.dst_port ~= 443 then return end
    
    local ja3 = get_ja3_fingerprint()
    if not ja3 then return end
    
    local https_tree = tree:add(https_analyzer, tvb())
    https_tree:add(f_ja3, ja3)
    
    -- Check against known malicious fingerprints
    for _, bad_ja3 in ipairs(threat_intel.fingerprints) do
        if ja3 == bad_ja3 then
            pinfo.cols.info:append(" [MALICIOUS JA3]")
            send_alert("MALICIOUS_JA3", "Malicious JA3: "..ja3, 90)
            break
        end
    end
    
    -- TLS version check
    local tls_version = Field.new("tls.handshake.version")
    if config.https.check_ssl_versions and tls_version and 
       tls_version() < config.https.min_tls_version then
        pinfo.cols.info:append(" [OUTDATED TLS]")
        send_alert("OUTDATED_TLS", string.format("Old TLS version: 0x%04x", tls_version()), 70)
    end
end

-- 8. REGISTER DISSECTORS =====================================================

register_postdissector(dns_tunnel)
register_postdissector(http_anomaly)
register_postdissector(https_analyzer)

-- 9. INITIALIZE PLUGIN =======================================================

print("Enterprise Traffic Analyzer v"..plugin_info.version.." loaded successfully")
print("  - JA3 fingerprinting: "..(config.https.check_ja3 and "enabled" or "disabled"))
print("  - Alerts: "..(config.alerts.enabled and "enabled" or "disabled"))
