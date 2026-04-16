--[[
    ╔══════════════════════════════════════════════════════════════╗
    ║                    Scanning-Lua v1.0.0                      ║
    ║          Scanner de Segurança para Roblox                   ║
    ║                                                              ║
    ║  Arquivo único para loadstring — Wave Executor               ║
    ║                                                              ║
    ║  Uso:                                                        ║
    ║    loadstring(game:HttpGet(                                   ║
    ║      "https://raw.githubusercontent.com/                     ║
    ║       oxomerketwere/Scanning-Lua/main/loader.lua"            ║
    ║    ))()                                                       ║
    ╚══════════════════════════════════════════════════════════════╝
]]

-- ================================================================
-- MÓDULO: Config
-- ================================================================
local Config = {}

Config.VERSION = "1.0.0"
Config.NAME = "Scanning-Lua"

Config.Logger = {
    MIN_LEVEL = "DEBUG",
    SAVE_TO_FILE = true,
    FILE_PREFIX = "scan_log",
    MAX_ENTRIES_PER_FILE = 10000,
    INCLUDE_TIMESTAMP = true,
    INCLUDE_STACKTRACE = true,
}

Config.Scanner = {
    SCAN_REMOTE_EVENTS = true,
    SCAN_REMOTE_FUNCTIONS = true,
    SCAN_BINDABLE_EVENTS = true,
    SCAN_HTTP_REQUESTS = true,
    SCAN_LOADSTRING = true,
    SCAN_REQUIRE = true,
    SCAN_DATASTORE = true,
    SCAN_MARKETPLACE = true,
    AUTO_SCAN_INTERVAL = 30,
    AUTO_SCAN_ENABLED = false,
    MAX_DEPTH = 50,
}

Config.Filters = {
    SUSPICIOUS_PATTERNS = {
        "loadstring",
        "HttpGet",
        "HttpPost",
        "GetObjects",
        "require%((%d+)%)",
        "game:GetService%(\"HttpService\"%)",
        "syn%.request",
        "http_request",
        "request",
        "getrawmetatable",
        "setrawmetatable",
        "hookfunction",
        "hookmetamethod",
        "newcclosure",
        "getnamecallmethod",
        "setnamecallmethod",
        "getgenv",
        "getrenv",
        "getfenv",
        "setfenv",
        "debug%.getupvalue",
        "debug%.setupvalue",
        "debug%.getinfo",
        "debug%.getconstant",
        "debug%.setconstant",
        "firesignal",
        "fireserver",
        "fireclickdetector",
        "firetouchinterest",
        "fireproximityprompt",
    },
    MONITORED_SERVICES = {
        "ReplicatedStorage",
        "ServerScriptService",
        "ServerStorage",
        "Workspace",
        "Players",
        "Lighting",
        "StarterGui",
        "StarterPack",
        "StarterPlayer",
    },
    SUSPICIOUS_REMOTE_NAMES = {
        ".*Event.*",
        ".*Remote.*",
        ".*Fire.*",
        ".*Send.*",
        ".*Invoke.*",
        ".*Handler.*",
        ".*Callback.*",
    },
    MIN_SEVERITY = "LOW",
}

Config.Vulnerability = {
    CATEGORIES = {
        "REMOTE_ABUSE",
        "CODE_INJECTION",
        "DATA_EXFILTRATION",
        "PRIVILEGE_ESCALATION",
        "MEMORY_MANIPULATION",
        "NETWORK_EXPLOIT",
        "AUTHENTICATION_BYPASS",
        "INPUT_VALIDATION",
    },
    AUTO_REPORT = true,
    REPORT_FORMAT = "json",
}

Config.Network = {
    MONITOR_HTTP = true,
    MONITOR_WEBSOCKET = true,
    ALLOWED_DOMAINS = {
        "roblox.com",
        "rbxcdn.com",
        "robloxcdn.com",
    },
    LOG_ALL_REQUESTS = false,
}

-- ================================================================
-- MÓDULO: JSON
-- ================================================================
local JSON = {}

local ESCAPE_MAP = {
    ["\\"] = "\\\\",
    ['"'] = '\\"',
    ["\n"] = "\\n",
    ["\r"] = "\\r",
    ["\t"] = "\\t",
    ["\b"] = "\\b",
    ["\f"] = "\\f",
}

local function escapeString(str)
    str = str:gsub('[\\"%c]', function(c)
        return ESCAPE_MAP[c] or string.format("\\u%04x", string.byte(c))
    end)
    return str
end

local function isArray(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    for i = 1, count do
        if tbl[i] == nil then
            return false
        end
    end
    return count > 0
end

function JSON.encode(value, indent, currentIndent)
    indent = indent or nil
    currentIndent = currentIndent or 0

    local valueType = type(value)

    if value == nil then
        return "null"
    elseif valueType == "boolean" then
        return tostring(value)
    elseif valueType == "number" then
        if value ~= value then return "null" end
        if value == math.huge then return "null" end
        if value == -math.huge then return "null" end
        return tostring(value)
    elseif valueType == "string" then
        return '"' .. escapeString(value) .. '"'
    elseif valueType == "table" then
        local parts = {}
        local newIndent = currentIndent + (indent or 0)
        local separator = indent and ",\n" or ","
        local padding = indent and string.rep(" ", newIndent) or ""
        local closePadding = indent and string.rep(" ", currentIndent) or ""
        local colon = indent and ": " or ":"

        if isArray(value) then
            for i = 1, #value do
                local encoded = JSON.encode(value[i], indent, newIndent)
                parts[#parts + 1] = padding .. encoded
            end
            if #parts == 0 then return "[]" end
            if indent then
                return "[\n" .. table.concat(parts, separator) .. "\n" .. closePadding .. "]"
            else
                local compactParts = {}
                for i = 1, #value do
                    compactParts[#compactParts + 1] = JSON.encode(value[i], indent, newIndent)
                end
                return "[" .. table.concat(compactParts, ",") .. "]"
            end
        else
            local keys = {}
            for k in pairs(value) do
                if type(k) == "string" or type(k) == "number" then
                    keys[#keys + 1] = k
                end
            end
            table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)

            for _, k in ipairs(keys) do
                local keyStr = '"' .. escapeString(tostring(k)) .. '"'
                local encoded = JSON.encode(value[k], indent, newIndent)
                parts[#parts + 1] = padding .. keyStr .. colon .. encoded
            end
            if #parts == 0 then return "{}" end
            if indent then
                return "{\n" .. table.concat(parts, separator) .. "\n" .. closePadding .. "}"
            else
                local compactParts = {}
                for _, k in ipairs(keys) do
                    local keyStr = '"' .. escapeString(tostring(k)) .. '"'
                    local encoded = JSON.encode(value[k], indent, newIndent)
                    compactParts[#compactParts + 1] = keyStr .. ":" .. encoded
                end
                return "{" .. table.concat(compactParts, ",") .. "}"
            end
        end
    else
        return "null"
    end
end

function JSON.encodePretty(value, indentSize)
    return JSON.encode(value, indentSize or 2, 0)
end

function JSON.decode(str)
    if type(str) ~= "string" then
        return nil, "Expected string, got " .. type(str)
    end

    local pos = 1

    local function skipWhitespace()
        pos = str:find("[^ \t\r\n]", pos) or (#str + 1)
    end

    local function peek()
        return str:sub(pos, pos)
    end

    local function consume(expected)
        if str:sub(pos, pos) ~= expected then return false end
        pos = pos + 1
        return true
    end

    local parseValue

    local function parseString()
        if not consume('"') then return nil, "Expected '\"' at position " .. pos end
        local result = {}
        while pos <= #str do
            local c = str:sub(pos, pos)
            if c == '"' then
                pos = pos + 1
                return table.concat(result)
            elseif c == '\\' then
                pos = pos + 1
                local esc = str:sub(pos, pos)
                if esc == '"' then result[#result + 1] = '"'
                elseif esc == '\\' then result[#result + 1] = '\\'
                elseif esc == '/' then result[#result + 1] = '/'
                elseif esc == 'n' then result[#result + 1] = '\n'
                elseif esc == 'r' then result[#result + 1] = '\r'
                elseif esc == 't' then result[#result + 1] = '\t'
                elseif esc == 'b' then result[#result + 1] = '\b'
                elseif esc == 'f' then result[#result + 1] = '\f'
                elseif esc == 'u' then
                    local hex = str:sub(pos + 1, pos + 4)
                    local codepoint = tonumber(hex, 16)
                    if codepoint then
                        if codepoint < 128 then
                            result[#result + 1] = string.char(codepoint)
                        else
                            result[#result + 1] = string.char(
                                192 + math.floor(codepoint / 64),
                                128 + (codepoint % 64)
                            )
                        end
                        pos = pos + 4
                    end
                end
                pos = pos + 1
            else
                result[#result + 1] = c
                pos = pos + 1
            end
        end
        return nil, "Unterminated string"
    end

    local function parseNumber()
        local startPos = pos
        if str:sub(pos, pos) == '-' then pos = pos + 1 end
        while pos <= #str and str:sub(pos, pos):match("%d") do pos = pos + 1 end
        if pos <= #str and str:sub(pos, pos) == '.' then
            pos = pos + 1
            while pos <= #str and str:sub(pos, pos):match("%d") do pos = pos + 1 end
        end
        if pos <= #str and str:sub(pos, pos):match("[eE]") then
            pos = pos + 1
            if pos <= #str and str:sub(pos, pos):match("[%+%-]") then pos = pos + 1 end
            while pos <= #str and str:sub(pos, pos):match("%d") do pos = pos + 1 end
        end
        local num = tonumber(str:sub(startPos, pos - 1))
        if not num then return nil, "Invalid number at position " .. startPos end
        return num
    end

    local function parseArray()
        if not consume('[') then return nil, "Expected '['" end
        local arr = {}
        skipWhitespace()
        if peek() == ']' then pos = pos + 1; return arr end
        while true do
            skipWhitespace()
            local val, err = parseValue()
            if err then return nil, err end
            arr[#arr + 1] = val
            skipWhitespace()
            if not consume(',') then break end
        end
        if not consume(']') then return nil, "Expected ']' at position " .. pos end
        return arr
    end

    local function parseObject()
        if not consume('{') then return nil, "Expected '{'" end
        local obj = {}
        skipWhitespace()
        if peek() == '}' then pos = pos + 1; return obj end
        while true do
            skipWhitespace()
            local key, err = parseString()
            if err then return nil, err end
            skipWhitespace()
            if not consume(':') then return nil, "Expected ':' at position " .. pos end
            skipWhitespace()
            local val
            val, err = parseValue()
            if err then return nil, err end
            obj[key] = val
            skipWhitespace()
            if not consume(',') then break end
        end
        if not consume('}') then return nil, "Expected '}' at position " .. pos end
        return obj
    end

    parseValue = function()
        skipWhitespace()
        local c = peek()
        if c == '"' then return parseString()
        elseif c == '{' then return parseObject()
        elseif c == '[' then return parseArray()
        elseif c == 't' then
            if str:sub(pos, pos + 3) == "true" then pos = pos + 4; return true end
            return nil, "Invalid value at position " .. pos
        elseif c == 'f' then
            if str:sub(pos, pos + 4) == "false" then pos = pos + 5; return false end
            return nil, "Invalid value at position " .. pos
        elseif c == 'n' then
            if str:sub(pos, pos + 3) == "null" then pos = pos + 4; return nil end
            return nil, "Invalid value at position " .. pos
        elseif c == '-' or c:match("%d") then return parseNumber()
        else return nil, "Unexpected character '" .. c .. "' at position " .. pos
        end
    end

    local result, err = parseValue()
    if err then return nil, err end
    return result
end

-- ================================================================
-- MÓDULO: Logger
-- ================================================================
local Logger = {}
Logger.__index = Logger

local LOG_LEVELS = { DEBUG = 1, INFO = 2, WARN = 3, ERROR = 4, CRITICAL = 5 }

function Logger.new(config)
    local self = setmetatable({}, Logger)
    self.config = config or {}
    self.minLevel = LOG_LEVELS[config.MIN_LEVEL] or LOG_LEVELS.DEBUG
    self.entries = {}
    self.sessionId = Logger._generateSessionId()
    self.startTime = os.time()
    self.entryCount = 0
    self.sessionMeta = {
        session_id = self.sessionId,
        start_time = os.date("!%Y-%m-%dT%H:%M:%SZ", self.startTime),
        scanner_version = Config.VERSION,
        log_level = config.MIN_LEVEL or "DEBUG",
    }
    return self
end

function Logger._generateSessionId()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return string.gsub(template, "[xy]", function(c)
        local v = (c == "x") and math.random(0, 15) or math.random(8, 11)
        return string.format("%x", v)
    end)
end

function Logger._getTimestamp()
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

function Logger:_createEntry(level, category, message, data)
    self.entryCount = self.entryCount + 1
    local entry = {
        id = self.entryCount,
        timestamp = Logger._getTimestamp(),
        level = level,
        category = category,
        message = message,
        session_id = self.sessionId,
    }
    if data then entry.data = data end
    if self.config.INCLUDE_STACKTRACE and (level == "ERROR" or level == "CRITICAL") then
        entry.stacktrace = debug.traceback("", 3)
    end
    return entry
end

function Logger:_log(level, category, message, data)
    local levelNum = LOG_LEVELS[level]
    if not levelNum or levelNum < self.minLevel then return end
    local entry = self:_createEntry(level, category, message, data)
    self.entries[#self.entries + 1] = entry
    local prefix = string.format("[%s][%s][%s]", entry.timestamp, level, category)
    print(prefix .. " " .. message)
    if self.config.MAX_ENTRIES_PER_FILE and #self.entries >= self.config.MAX_ENTRIES_PER_FILE then
        self:flush()
    end
    return entry
end

function Logger:debug(category, message, data) return self:_log("DEBUG", category, message, data) end
function Logger:info(category, message, data) return self:_log("INFO", category, message, data) end
function Logger:warn(category, message, data) return self:_log("WARN", category, message, data) end
function Logger:error(category, message, data) return self:_log("ERROR", category, message, data) end
function Logger:critical(category, message, data) return self:_log("CRITICAL", category, message, data) end

function Logger:flush(filename)
    if #self.entries == 0 then return true end
    local logData = {
        metadata = self.sessionMeta,
        total_entries = #self.entries,
        entries = self.entries,
    }
    local jsonStr = JSON.encodePretty(logData)

    -- Tentar salvar via writefile (disponível na maioria dos executors Roblox)
    local saved = false
    if writefile then
        local fname = filename or string.format("ScanningLua/scan_log_%s.json", os.date("!%Y%m%d_%H%M%S"))
        local ok = pcall(function() writefile(fname, jsonStr) end)
        if ok then
            print("[Logger] " .. #self.entries .. " entradas salvas em: " .. fname)
            saved = true
        end
    end

    -- Fallback: io.open (Lua padrão)
    if not saved then
        local fname = filename or string.format("scan_log_%s.json", os.date("!%Y%m%d_%H%M%S"))
        local file = io.open(fname, "w")
        if file then
            file:write(jsonStr)
            file:close()
            print("[Logger] " .. #self.entries .. " entradas salvas em: " .. fname)
            saved = true
        end
    end

    if not saved then
        print("[Logger] Não foi possível salvar em arquivo. JSON no console:")
        print(jsonStr)
    end

    self.entries = {}
    self.entryCount = 0
    return true
end

function Logger:toJSON()
    local logData = {
        metadata = self.sessionMeta,
        total_entries = #self.entries,
        entries = self.entries,
    }
    return JSON.encodePretty(logData)
end

function Logger:getStats()
    local stats = {
        session_id = self.sessionId,
        total_entries = #self.entries,
        by_level = { DEBUG = 0, INFO = 0, WARN = 0, ERROR = 0, CRITICAL = 0 },
    }
    for _, entry in ipairs(self.entries) do
        if stats.by_level[entry.level] then
            stats.by_level[entry.level] = stats.by_level[entry.level] + 1
        end
    end
    return stats
end

function Logger:close()
    self:info("LOGGER", "Encerrando sessão de log", {
        session_id = self.sessionId,
        duration_seconds = os.time() - self.startTime,
        total_entries = #self.entries,
    })
    self:flush()
end

-- ================================================================
-- MÓDULO: Filters
-- ================================================================
local Filters = {}
Filters.__index = Filters

local SEVERITY_LEVELS = { LOW = 1, MEDIUM = 2, HIGH = 3, CRITICAL = 4 }

function Filters.new(config, logger)
    local self = setmetatable({}, Filters)
    self.config = config or {}
    self.logger = logger
    self.minSeverity = SEVERITY_LEVELS[config.MIN_SEVERITY] or SEVERITY_LEVELS.LOW
    self.matchHistory = {}
    self.stats = {
        total_scanned = 0,
        total_matches = 0,
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        by_category = {},
    }
    return self
end

function Filters:classifySeverity(pattern)
    local criticalPatterns = {
        "getrawmetatable", "setrawmetatable", "hookfunction", "hookmetamethod",
        "debug%.setupvalue", "debug%.setconstant", "setfenv",
    }
    for _, cp in ipairs(criticalPatterns) do
        if pattern:find(cp, 1, true) then return "CRITICAL" end
    end

    local highPatterns = {
        "loadstring", "HttpGet", "HttpPost", "syn%.request",
        "http_request", "getfenv", "getrenv", "getgenv",
    }
    for _, hp in ipairs(highPatterns) do
        if pattern:find(hp, 1, true) then return "HIGH" end
    end

    local mediumPatterns = {
        "getnamecallmethod", "setnamecallmethod", "newcclosure",
        "firesignal", "fireserver", "fireclickdetector",
        "firetouchinterest", "fireproximityprompt",
        "debug%.getupvalue", "debug%.getinfo", "debug%.getconstant",
    }
    for _, mp in ipairs(mediumPatterns) do
        if pattern:find(mp, 1, true) then return "MEDIUM" end
    end

    return "LOW"
end

function Filters:analyzeCode(code, source)
    if type(code) ~= "string" then return {} end
    self.stats.total_scanned = self.stats.total_scanned + 1
    local matches = {}
    local patterns = self.config.SUSPICIOUS_PATTERNS or {}

    for _, pattern in ipairs(patterns) do
        local startPos = 1
        while true do
            local matchStart, matchEnd = code:find(pattern, startPos)
            if not matchStart then break end
            local matchedText = code:sub(matchStart, matchEnd)
            local severity = self:classifySeverity(pattern)
            local severityLevel = SEVERITY_LEVELS[severity] or 0

            if severityLevel >= self.minSeverity then
                local lineNum = 1
                for _ in code:sub(1, matchStart):gmatch("\n") do lineNum = lineNum + 1 end
                local lineStart = code:sub(1, matchStart):match(".*\n()") or 1
                local lineEnd = code:find("\n", matchEnd) or #code
                local line = code:sub(lineStart, lineEnd):gsub("^%s+", ""):gsub("%s+$", "")

                local match = {
                    pattern = pattern,
                    matched_text = matchedText,
                    severity = severity,
                    source = source,
                    line_number = lineNum,
                    line_content = line,
                    position = { start = matchStart, finish = matchEnd },
                    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                }
                matches[#matches + 1] = match
                self.stats.total_matches = self.stats.total_matches + 1
                self.stats.by_severity[severity] = (self.stats.by_severity[severity] or 0) + 1

                if self.logger then
                    self.logger:warn("FILTER", string.format(
                        "Padrão suspeito encontrado: '%s' em %s (linha %d) [%s]",
                        matchedText, source, lineNum, severity
                    ), match)
                end
            end
            startPos = matchEnd + 1
        end
    end

    if #matches > 0 then
        self.matchHistory[#self.matchHistory + 1] = {
            source = source,
            matches = matches,
            scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
    end
    return matches
end

function Filters:analyzeRemoteName(name, remotePath)
    local suspiciousNames = self.config.SUSPICIOUS_REMOTE_NAMES or {}
    for _, pattern in ipairs(suspiciousNames) do
        if name:match(pattern) then
            local match = {
                type = "SUSPICIOUS_REMOTE_NAME",
                name = name,
                path = remotePath,
                pattern = pattern,
                severity = "MEDIUM",
                timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            }
            if self.logger then
                self.logger:info("FILTER", string.format(
                    "Remote com nome suspeito: '%s' em %s", name, remotePath
                ), match)
            end
            return match
        end
    end
    return nil
end

function Filters:isMonitoredService(serviceName)
    for _, svc in ipairs(self.config.MONITORED_SERVICES or {}) do
        if svc == serviceName then return true end
    end
    return false
end

function Filters:analyzeRemoteArgs(args, remoteName)
    local alerts = {}
    if type(args) ~= "table" then return alerts end

    for i, arg in ipairs(args) do
        local argType = type(arg)
        if argType == "string" and #arg > 10000 then
            alerts[#alerts + 1] = {
                type = "OVERSIZED_ARGUMENT",
                remote = remoteName,
                arg_index = i,
                arg_size = #arg,
                severity = "HIGH",
                description = "Argumento string excessivamente grande (possível buffer overflow)",
            }
        end
        if argType == "string" then
            local codeIndicators = { "function%(", "local%s+", "require%(", "loadstring%(" }
            for _, indicator in ipairs(codeIndicators) do
                if arg:find(indicator) then
                    alerts[#alerts + 1] = {
                        type = "CODE_IN_ARGUMENT",
                        remote = remoteName,
                        arg_index = i,
                        pattern = indicator,
                        severity = "HIGH",
                        description = "Código Lua detectado em argumento de Remote",
                    }
                    break
                end
            end
        end
        if argType == "number" and (arg > 2147483647 or arg < -2147483648) then
            alerts[#alerts + 1] = {
                type = "INTEGER_OVERFLOW_ATTEMPT",
                remote = remoteName,
                arg_index = i,
                value = arg,
                severity = "MEDIUM",
                description = "Valor numérico fora dos limites de int32",
            }
        end
    end

    if #alerts > 0 and self.logger then
        for _, alert in ipairs(alerts) do
            self.logger:warn("FILTER", string.format(
                "Alerta em argumentos de '%s': %s [%s]",
                remoteName, alert.description, alert.severity
            ), alert)
        end
    end
    return alerts
end

function Filters:getStats() return self.stats end
function Filters:getHistory() return self.matchHistory end
function Filters:reset()
    self.matchHistory = {}
    self.stats = {
        total_scanned = 0, total_matches = 0,
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        by_category = {},
    }
end

-- ================================================================
-- MÓDULO: Scanner
-- ================================================================
local Scanner = {}
Scanner.__index = Scanner

function Scanner.new(config, logger, filters)
    local self = setmetatable({}, Scanner)
    self.config = config or {}
    self.logger = logger
    self.filters = filters
    self.results = {
        remote_events = {},
        remote_functions = {},
        bindable_events = {},
        scripts = {},
        http_requests = {},
        datastore_access = {},
        suspicious_items = {},
        vulnerabilities = {},
    }
    self.scanCount = 0
    self.isScanning = false
    return self
end

function Scanner:scanInstance(instance, depth)
    depth = depth or 0
    if depth > (self.config.MAX_DEPTH or 50) then return end
    if not instance then return end

    local name = instance.Name or "unnamed"
    local className = instance.ClassName or "unknown"
    local fullPath = ""
    pcall(function() fullPath = instance:GetFullName() end)
    if fullPath == "" then fullPath = name end

    if className == "RemoteEvent" and self.config.SCAN_REMOTE_EVENTS then
        self:_registerRemote(instance, fullPath, "RemoteEvent", self.results.remote_events)
    end
    if className == "RemoteFunction" and self.config.SCAN_REMOTE_FUNCTIONS then
        self:_registerRemote(instance, fullPath, "RemoteFunction", self.results.remote_functions)
    end
    if className == "BindableEvent" and self.config.SCAN_BINDABLE_EVENTS then
        local entry = {
            name = name, path = fullPath, class = "BindableEvent",
            scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
        self.results.bindable_events[#self.results.bindable_events + 1] = entry
        if self.logger then self.logger:debug("SCANNER", "BindableEvent: " .. fullPath) end
    end

    if className == "LocalScript" or className == "Script" or className == "ModuleScript" then
        self:_scanScript(instance, fullPath, className)
    end

    -- Filhos
    local children = {}
    pcall(function() children = instance:GetChildren() end)
    if type(children) ~= "table" then children = instance.children or {} end
    for _, child in ipairs(children) do
        self:scanInstance(child, depth + 1)
    end
end

function Scanner:_registerRemote(instance, path, class, resultTable)
    local entry = {
        name = instance.Name,
        path = path,
        class = class,
        scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        parent = "",
    }
    pcall(function() entry.parent = instance.Parent and instance.Parent.Name or "nil" end)
    resultTable[#resultTable + 1] = entry

    if self.filters then
        local nameMatch = self.filters:analyzeRemoteName(instance.Name, path)
        if nameMatch then
            entry.suspicious = true
            entry.filter_match = nameMatch
            self.results.suspicious_items[#self.results.suspicious_items + 1] = {
                type = "SUSPICIOUS_" .. class:upper(),
                details = entry,
            }
        end
    end
    if self.logger then
        self.logger:info("SCANNER", class .. " encontrado: " .. path, entry)
    end
end

function Scanner:_scanScript(instance, path, scriptType)
    local source = nil
    pcall(function() source = instance.Source end)
    if not source then
        pcall(function()
            if decompile then source = decompile(instance) end
        end)
    end

    local entry = {
        name = instance.Name, path = path, class = scriptType,
        has_source = source ~= nil,
        source_length = source and #source or 0,
        scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    }
    pcall(function() entry.enabled = instance.Enabled ~= false end)

    if source and self.filters then
        local matches = self.filters:analyzeCode(source, path)
        if #matches > 0 then
            entry.suspicious = true
            entry.filter_matches = matches
            entry.match_count = #matches
            for _, match in ipairs(matches) do
                self.results.suspicious_items[#self.results.suspicious_items + 1] = {
                    type = "SUSPICIOUS_CODE",
                    script_path = path,
                    details = match,
                }
            end
            if self.logger then
                self.logger:warn("SCANNER", string.format(
                    "Script com %d padrões suspeitos: %s", #matches, path
                ))
            end
        end
    end
    self.results.scripts[#self.results.scripts + 1] = entry
end

function Scanner:scanServices(gameRef)
    if not gameRef then
        if self.logger then self.logger:error("SCANNER", "Objeto 'game' não disponível") end
        return
    end
    self.isScanning = true
    self.scanCount = self.scanCount + 1
    if self.logger then
        self.logger:info("SCANNER", string.format("Iniciando scan #%d dos serviços", self.scanCount))
    end

    local services = {
        "ReplicatedStorage", "ReplicatedFirst", "ServerScriptService", "ServerStorage",
        "Workspace", "Players", "Lighting", "StarterGui", "StarterPack",
        "StarterPlayer", "Chat", "SoundService", "Teams",
    }
    for _, svcName in ipairs(services) do
        local ok, svc = pcall(function() return gameRef:GetService(svcName) end)
        if ok and svc then
            if self.logger then self.logger:debug("SCANNER", "Escaneando: " .. svcName) end
            self:scanInstance(svc, 0)
        end
    end
    self.isScanning = false
    if self.logger then
        self.logger:info("SCANNER", "Scan de serviços concluído", self:getSummary())
    end
end

function Scanner:monitorRemote(remote, callback)
    if not remote then return nil end
    local connection
    pcall(function()
        if remote.OnClientEvent then
            connection = remote.OnClientEvent:Connect(function(...)
                local args = { ... }
                local entry = {
                    remote_name = remote.Name,
                    args = args, arg_count = #args,
                    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                }
                pcall(function() entry.remote_path = remote:GetFullName() end)
                if self.filters then
                    local alerts = self.filters:analyzeRemoteArgs(args, remote.Name)
                    if #alerts > 0 then entry.alerts = alerts end
                end
                if self.logger then
                    self.logger:info("MONITOR", string.format(
                        "Remote interceptado: %s (%d args)", remote.Name, #args
                    ), entry)
                end
                if callback then callback(entry) end
            end)
        end
    end)
    return connection
end

function Scanner:getSummary()
    return {
        scan_count = self.scanCount,
        remote_events = #self.results.remote_events,
        remote_functions = #self.results.remote_functions,
        bindable_events = #self.results.bindable_events,
        scripts_analyzed = #self.results.scripts,
        http_requests_logged = #self.results.http_requests,
        suspicious_items = #self.results.suspicious_items,
        vulnerabilities = #self.results.vulnerabilities,
    }
end

function Scanner:exportResults()
    local report = {
        scanner_version = Config.VERSION,
        scan_count = self.scanCount,
        export_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        summary = self:getSummary(),
        results = self.results,
    }
    return JSON.encodePretty(report)
end

function Scanner:saveResults(filepath)
    local jsonStr = self:exportResults()
    local saved = false
    if writefile then
        local ok = pcall(function() writefile(filepath, jsonStr) end)
        if ok then saved = true end
    end
    if not saved then
        local file = io.open(filepath, "w")
        if file then file:write(jsonStr); file:close(); saved = true end
    end
    if saved and self.logger then
        self.logger:info("SCANNER", "Resultados salvos em: " .. filepath)
    end
    return saved
end

function Scanner:getResults() return self.results end

function Scanner:reset()
    self.results = {
        remote_events = {}, remote_functions = {}, bindable_events = {},
        scripts = {}, http_requests = {}, datastore_access = {},
        suspicious_items = {}, vulnerabilities = {},
    }
    self.scanCount = 0
end

-- ================================================================
-- MÓDULO: Vulnerability Detector
-- ================================================================
local VulnerabilityDetector = {}
VulnerabilityDetector.__index = VulnerabilityDetector

local VULN_DATABASE = {
    {
        id = "VULN-RE-001", name = "RemoteEvent sem validação de servidor",
        category = "REMOTE_ABUSE", severity = "HIGH",
        description = "RemoteEvent que não valida dados recebidos do cliente pode permitir manipulação de dados.",
        indicators = { "OnServerEvent", "FireServer" },
        remediation = "Implementar validação de tipo e limites em todos os dados recebidos via RemoteEvent.",
    },
    {
        id = "VULN-RE-002", name = "RemoteEvent exposto sem rate limiting",
        category = "REMOTE_ABUSE", severity = "MEDIUM",
        description = "RemoteEvents sem controle de frequência podem ser explorados para spam ou DoS.",
        indicators = { "RemoteEvent", "FireServer" },
        remediation = "Implementar rate limiting no handler do servidor.",
    },
    {
        id = "VULN-CI-001", name = "Uso de loadstring",
        category = "CODE_INJECTION", severity = "CRITICAL",
        description = "loadstring permite execução de código arbitrário.",
        indicators = { "loadstring" },
        remediation = "Evitar loadstring. Usar módulos pré-compilados.",
    },
    {
        id = "VULN-CI-002", name = "Require dinâmico com ID variável",
        category = "CODE_INJECTION", severity = "HIGH",
        description = "Require com IDs dinâmicos pode carregar módulos maliciosos.",
        indicators = { "require" },
        remediation = "Usar apenas IDs de módulo estáticos.",
    },
    {
        id = "VULN-DE-001", name = "Requisição HTTP para domínio externo",
        category = "DATA_EXFILTRATION", severity = "HIGH",
        description = "Requisições HTTP para domínios não-Roblox podem indicar exfiltração de dados.",
        indicators = { "HttpGet", "HttpPost", "request", "syn.request", "http_request" },
        remediation = "Usar whitelist de domínios.",
    },
    {
        id = "VULN-MM-001", name = "Manipulação de metatables",
        category = "MEMORY_MANIPULATION", severity = "CRITICAL",
        description = "Modificação de metatables pode alterar o comportamento de objetos do jogo.",
        indicators = { "getrawmetatable", "setrawmetatable" },
        remediation = "Proteger metatables com __metatable.",
    },
    {
        id = "VULN-MM-002", name = "Hook de funções",
        category = "MEMORY_MANIPULATION", severity = "CRITICAL",
        description = "Hooking permite interceptar e modificar chamadas de função.",
        indicators = { "hookfunction", "hookmetamethod" },
        remediation = "Implementar verificação de integridade de funções críticas.",
    },
    {
        id = "VULN-PE-001", name = "Acesso a ambiente global",
        category = "PRIVILEGE_ESCALATION", severity = "HIGH",
        description = "Acesso ao ambiente global permite modificar variáveis compartilhadas.",
        indicators = { "getgenv", "getrenv", "getfenv", "setfenv" },
        remediation = "Isolar ambientes de execução.",
    },
    {
        id = "VULN-PE-002", name = "Manipulação de upvalues/constantes",
        category = "PRIVILEGE_ESCALATION", severity = "HIGH",
        description = "Manipulação de upvalues pode alterar lógica de segurança.",
        indicators = { "debug.getupvalue", "debug.setupvalue", "debug.getconstant", "debug.setconstant" },
        remediation = "Evitar dados sensíveis em upvalues.",
    },
    {
        id = "VULN-IV-001", name = "Simulação de input do jogador",
        category = "INPUT_VALIDATION", severity = "MEDIUM",
        description = "Simulação de clicks e toques pode contornar verificações.",
        indicators = { "fireclickdetector", "firetouchinterest", "fireproximityprompt", "firesignal" },
        remediation = "Validação server-side para todas as interações.",
    },
    {
        id = "VULN-AB-001", name = "Bypass de namecall",
        category = "AUTHENTICATION_BYPASS", severity = "HIGH",
        description = "Manipulação de namecall permite alterar métodos chamados.",
        indicators = { "getnamecallmethod", "setnamecallmethod" },
        remediation = "Verificações server-side independentes do método de chamada.",
    },
}

function VulnerabilityDetector.new(config, logger)
    local self = setmetatable({}, VulnerabilityDetector)
    self.config = config or {}
    self.logger = logger
    self.detectedVulnerabilities = {}
    self.stats = {
        total_detected = 0,
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        by_category = {},
    }
    return self
end

function VulnerabilityDetector:_isDuplicate(vuln)
    for _, existing in ipairs(self.detectedVulnerabilities) do
        if existing.vuln_id == vuln.vuln_id
            and existing.source == vuln.source
            and existing.line_number == vuln.line_number then
            return true
        end
    end
    return false
end

function VulnerabilityDetector:analyzeFilterResults(filterMatches, source)
    local vulnerabilities = {}
    for _, match in ipairs(filterMatches) do
        for _, vulnDef in ipairs(VULN_DATABASE) do
            for _, indicator in ipairs(vulnDef.indicators) do
                if match.matched_text and match.matched_text:find(indicator, 1, true) then
                    local vuln = {
                        vuln_id = vulnDef.id,
                        name = vulnDef.name,
                        category = vulnDef.category,
                        severity = vulnDef.severity,
                        description = vulnDef.description,
                        remediation = vulnDef.remediation,
                        source = source,
                        matched_text = match.matched_text,
                        line_number = match.line_number,
                        line_content = match.line_content,
                        detection_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                    }
                    if not self:_isDuplicate(vuln) then
                        vulnerabilities[#vulnerabilities + 1] = vuln
                        self.detectedVulnerabilities[#self.detectedVulnerabilities + 1] = vuln
                        self.stats.total_detected = self.stats.total_detected + 1
                        self.stats.by_severity[vulnDef.severity] = (self.stats.by_severity[vulnDef.severity] or 0) + 1
                        self.stats.by_category[vulnDef.category] = (self.stats.by_category[vulnDef.category] or 0) + 1
                        if self.logger then
                            self.logger:warn("VULN", string.format(
                                "[%s] %s em %s (linha %s) - %s",
                                vuln.vuln_id, vuln.name, source,
                                tostring(vuln.line_number), vuln.severity
                            ), vuln)
                        end
                    end
                    break
                end
            end
        end
    end
    return vulnerabilities
end

function VulnerabilityDetector:analyzeScanResults(scanResults)
    if not scanResults then return end
    if self.logger then
        self.logger:info("VULN_DETECTOR", "Iniciando análise de vulnerabilidades")
    end

    for _, script in ipairs(scanResults.scripts or {}) do
        if script.suspicious and script.filter_matches then
            self:analyzeFilterResults(script.filter_matches, script.path)
        end
    end

    for _, remote in ipairs(scanResults.remote_events or {}) do
        if remote.suspicious then
            local vuln = {
                vuln_id = "VULN-RE-DYNAMIC", name = "RemoteEvent potencialmente vulnerável",
                category = "REMOTE_ABUSE", severity = "MEDIUM",
                description = string.format("RemoteEvent '%s' com nome suspeito.", remote.name),
                remediation = "Revisar handler server-side.",
                source = remote.path,
                detection_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            }
            if not self:_isDuplicate(vuln) then
                self.detectedVulnerabilities[#self.detectedVulnerabilities + 1] = vuln
                self.stats.total_detected = self.stats.total_detected + 1
                self.stats.by_severity["MEDIUM"] = (self.stats.by_severity["MEDIUM"] or 0) + 1
            end
        end
    end

    for _, httpReq in ipairs(scanResults.http_requests or {}) do
        local vuln = {
            vuln_id = "VULN-DE-DYNAMIC", name = "Requisição HTTP detectada",
            category = "DATA_EXFILTRATION", severity = "HIGH",
            description = string.format("Requisição HTTP para '%s'.", httpReq.url or "unknown"),
            remediation = "Verificar se a requisição é legítima.",
            source = httpReq.url or "unknown",
            detection_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
        if not self:_isDuplicate(vuln) then
            self.detectedVulnerabilities[#self.detectedVulnerabilities + 1] = vuln
            self.stats.total_detected = self.stats.total_detected + 1
            self.stats.by_severity["HIGH"] = (self.stats.by_severity["HIGH"] or 0) + 1
        end
    end

    if self.logger then
        self.logger:info("VULN_DETECTOR", string.format(
            "Análise concluída: %d vulnerabilidades", self.stats.total_detected
        ), self.stats)
    end
end

function VulnerabilityDetector:_calculateRiskLevel()
    if self.stats.by_severity.CRITICAL > 0 then return "CRITICAL"
    elseif self.stats.by_severity.HIGH > 0 then return "HIGH"
    elseif self.stats.by_severity.MEDIUM > 0 then return "MEDIUM"
    elseif self.stats.by_severity.LOW > 0 then return "LOW"
    else return "NONE" end
end

function VulnerabilityDetector:_generateRecommendations()
    local recommendations = {}
    local seenCategories = {}
    local recMap = {
        REMOTE_ABUSE = "Implementar validação rigorosa de dados em todos os RemoteEvents/Functions. Adicionar rate limiting.",
        CODE_INJECTION = "Eliminar uso de loadstring e require dinâmico. Usar módulos pré-compilados.",
        DATA_EXFILTRATION = "Implementar whitelist de domínios para requisições HTTP.",
        MEMORY_MANIPULATION = "Proteger metatables críticas. Verificar integridade de funções.",
        PRIVILEGE_ESCALATION = "Isolar ambientes de execução. Evitar dados sensíveis em upvalues.",
        AUTHENTICATION_BYPASS = "Implementar verificações server-side independentes.",
        INPUT_VALIDATION = "Validar todas as interações no servidor. Implementar cooldowns.",
        NETWORK_EXPLOIT = "Monitorar e limitar tráfego de rede.",
    }
    for _, vuln in ipairs(self.detectedVulnerabilities) do
        if not seenCategories[vuln.category] then
            seenCategories[vuln.category] = true
            recommendations[#recommendations + 1] = {
                category = vuln.category,
                priority = vuln.severity,
                recommendation = recMap[vuln.category] or "Revisar vulnerabilidades desta categoria.",
            }
        end
    end
    return recommendations
end

function VulnerabilityDetector:generateReport()
    local severityOrder = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4 }
    local sorted = {}
    for _, v in ipairs(self.detectedVulnerabilities) do sorted[#sorted + 1] = v end
    table.sort(sorted, function(a, b)
        return (severityOrder[a.severity] or 5) < (severityOrder[b.severity] or 5)
    end)
    return {
        report_version = "1.0.0",
        generated_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        summary = {
            total_vulnerabilities = self.stats.total_detected,
            by_severity = self.stats.by_severity,
            by_category = self.stats.by_category,
            risk_level = self:_calculateRiskLevel(),
        },
        vulnerabilities = sorted,
        recommendations = self:_generateRecommendations(),
    }
end

function VulnerabilityDetector:exportReportJSON()
    return JSON.encodePretty(self:generateReport())
end

function VulnerabilityDetector:saveReport(filepath)
    local jsonStr = self:exportReportJSON()
    local saved = false
    if writefile then
        local ok = pcall(function() writefile(filepath, jsonStr) end)
        if ok then saved = true end
    end
    if not saved then
        local file = io.open(filepath, "w")
        if file then file:write(jsonStr); file:close(); saved = true end
    end
    if saved and self.logger then
        self.logger:info("VULN_DETECTOR", "Relatório salvo em: " .. filepath)
    end
    return saved
end

function VulnerabilityDetector:getVulnerabilities() return self.detectedVulnerabilities end
function VulnerabilityDetector:getStats() return self.stats end
function VulnerabilityDetector:reset()
    self.detectedVulnerabilities = {}
    self.stats = {
        total_detected = 0,
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        by_category = {},
    }
end

-- ================================================================
-- MÓDULO: Network Monitor
-- ================================================================
local NetworkMonitor = {}
NetworkMonitor.__index = NetworkMonitor

function NetworkMonitor.new(config, logger)
    local self = setmetatable({}, NetworkMonitor)
    self.config = config or {}
    self.logger = logger
    self.requestLog = {}
    self.blockedRequests = {}
    self.hooks = {}
    self.stats = {
        total_requests = 0, blocked_requests = 0, suspicious_requests = 0,
        by_method = {}, by_domain = {},
    }
    return self
end

function NetworkMonitor.extractDomain(url)
    if type(url) ~= "string" then return nil end
    local domain = url:match("^https?://([^/]+)") or url:match("^([^/]+)")
    if domain then domain = domain:match("^([^:]+)") end
    return domain
end

function NetworkMonitor:isDomainAllowed(domain)
    if not domain then return false end
    domain = domain:lower()
    for _, allowed in ipairs(self.config.ALLOWED_DOMAINS or {}) do
        if domain == allowed:lower() or domain:match("%." .. allowed:lower():gsub("%.", "%%.") .. "$") then
            return true
        end
    end
    return false
end

function NetworkMonitor:logRequest(method, url, headers, body)
    local domain = NetworkMonitor.extractDomain(url)
    local isAllowed = self:isDomainAllowed(domain)
    local isSuspicious = not isAllowed

    local entry = {
        id = #self.requestLog + 1,
        method = method or "UNKNOWN",
        url = url, domain = domain,
        is_allowed = isAllowed, is_suspicious = isSuspicious,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        has_body = body ~= nil and #(body or "") > 0,
        body_size = body and #body or 0,
    }
    self.requestLog[#self.requestLog + 1] = entry
    self.stats.total_requests = self.stats.total_requests + 1
    self.stats.by_method[method] = (self.stats.by_method[method] or 0) + 1
    self.stats.by_domain[domain or "unknown"] = (self.stats.by_domain[domain or "unknown"] or 0) + 1

    if isSuspicious then
        self.stats.suspicious_requests = self.stats.suspicious_requests + 1
        self.blockedRequests[#self.blockedRequests + 1] = entry
        if self.logger then
            self.logger:warn("NETWORK", string.format(
                "Requisição suspeita: %s %s (domínio: %s)", method, url, domain or "unknown"
            ), entry)
        end
    elseif self.config.LOG_ALL_REQUESTS and self.logger then
        self.logger:debug("NETWORK", string.format("Requisição: %s %s", method, url), entry)
    end
    return entry
end

function NetworkMonitor:installHooks()
    if not self.config.MONITOR_HTTP then return end
    if self.logger then self.logger:info("NETWORK", "Instalando hooks de rede") end

    local selfRef = self

    pcall(function()
        if hookfunction and game and game.HttpGet then
            local original = hookfunction(game.HttpGet, function(gameRef, url, ...)
                selfRef:logRequest("GET", url)
                return original(gameRef, url, ...)
            end)
            selfRef.hooks.httpGet = original
        end
    end)

    pcall(function()
        if hookfunction and game and game.HttpPost then
            local original = hookfunction(game.HttpPost, function(gameRef, url, body, ...)
                selfRef:logRequest("POST", url, nil, body)
                return original(gameRef, url, body, ...)
            end)
            selfRef.hooks.httpPost = original
        end
    end)

    pcall(function()
        local requestFn = syn and syn.request or http_request or request
        if hookfunction and requestFn then
            local original = hookfunction(requestFn, function(opts, ...)
                local m = opts and opts.Method or "GET"
                local u = opts and opts.Url or "unknown"
                local b = opts and opts.Body
                selfRef:logRequest(m, u, nil, b)
                return original(opts, ...)
            end)
            selfRef.hooks.request = original
        end
    end)
end

function NetworkMonitor:analyzeTraffic()
    local alerts = {}
    for domain, count in pairs(self.stats.by_domain) do
        if not self:isDomainAllowed(domain) then
            alerts[#alerts + 1] = {
                type = "UNAUTHORIZED_DOMAIN", domain = domain,
                request_count = count, severity = "HIGH",
                description = string.format("Domínio não autorizado '%s' (%d requisições)", domain, count),
            }
        end
    end
    if self.stats.total_requests > 100 then
        alerts[#alerts + 1] = {
            type = "HIGH_REQUEST_VOLUME", total = self.stats.total_requests,
            severity = "MEDIUM",
            description = string.format("Volume alto: %d requisições", self.stats.total_requests),
        }
    end
    return alerts
end

function NetworkMonitor:getRequestLog() return self.requestLog end
function NetworkMonitor:getBlockedRequests() return self.blockedRequests end
function NetworkMonitor:getStats() return self.stats end

function NetworkMonitor:exportJSON()
    return JSON.encodePretty({
        export_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        stats = self.stats,
        alerts = self:analyzeTraffic(),
        request_log = self.requestLog,
        blocked_requests = self.blockedRequests,
    })
end

function NetworkMonitor:reset()
    self.requestLog = {}
    self.blockedRequests = {}
    self.stats = {
        total_requests = 0, blocked_requests = 0, suspicious_requests = 0,
        by_method = {}, by_domain = {},
    }
end

-- ================================================================
-- INICIALIZAÇÃO & API PRINCIPAL
-- ================================================================
print("============================================")
print("  Scanning-Lua v" .. Config.VERSION)
print("  Scanner de Segurança para Roblox")
print("  Carregado via loadstring")
print("============================================")

-- Criar pasta de saída (executor Roblox)
pcall(function()
    if makefolder then
        makefolder("ScanningLua")
        makefolder("ScanningLua/logs")
        makefolder("ScanningLua/reports")
    end
end)

local logger = Logger.new(Config.Logger)
logger:info("MAIN", "Scanning-Lua inicializado", { version = Config.VERSION })

local filters = Filters.new(Config.Filters, logger)
local scanner = Scanner.new(Config.Scanner, logger, filters)
local vulnDetector = VulnerabilityDetector.new(Config.Vulnerability, logger)
local networkMonitor = NetworkMonitor.new(Config.Network, logger)

logger:info("MAIN", "Todos os módulos carregados")

-- API pública
local ScanningLua = {}

function ScanningLua.fullScan(gameInstance)
    local target = gameInstance or game

    logger:info("MAIN", "========== SCAN COMPLETO INICIADO ==========")

    logger:info("MAIN", "[1/4] Instalando monitor de rede...")
    networkMonitor:installHooks()

    if target then
        logger:info("MAIN", "[2/4] Escaneando serviços do jogo...")
        scanner:scanServices(target)
    else
        logger:warn("MAIN", "[2/4] Objeto 'game' não disponível")
    end

    logger:info("MAIN", "[3/4] Analisando vulnerabilidades...")
    vulnDetector:analyzeScanResults(scanner:getResults())

    logger:info("MAIN", "[4/4] Analisando tráfego de rede...")
    local networkAlerts = networkMonitor:analyzeTraffic()

    local summary = {
        scan_results = scanner:getSummary(),
        vulnerability_stats = vulnDetector:getStats(),
        network_stats = networkMonitor:getStats(),
        network_alerts = #networkAlerts,
        filter_stats = filters:getStats(),
    }

    logger:info("MAIN", "========== SCAN COMPLETO FINALIZADO ==========", summary)
    ScanningLua.saveAllResults()
    return summary
end

function ScanningLua.scanCode(code, sourceName)
    sourceName = sourceName or "direct_input"
    logger:info("MAIN", string.format("Analisando código: %s (%d chars)", sourceName, #code))
    local filterMatches = filters:analyzeCode(code, sourceName)
    local vulnerabilities = vulnDetector:analyzeFilterResults(filterMatches, sourceName)
    return {
        source = sourceName,
        code_length = #code,
        filter_matches = filterMatches,
        match_count = #filterMatches,
        vulnerabilities = vulnerabilities,
        vulnerability_count = #vulnerabilities,
    }
end

function ScanningLua.scanScript(scriptInstance)
    if not scriptInstance then return end
    local source = nil
    pcall(function() source = scriptInstance.Source end)
    if not source then
        pcall(function() if decompile then source = decompile(scriptInstance) end end)
    end
    if source then
        local name = "unknown"
        pcall(function() name = scriptInstance:GetFullName() end)
        return ScanningLua.scanCode(source, name)
    end
    logger:warn("MAIN", "Não foi possível obter o source do script")
    return nil
end

function ScanningLua.monitorRemote(remote, callback)
    return scanner:monitorRemote(remote, callback)
end

function ScanningLua.monitorAllRemotes(callback)
    local remotes = scanner:getResults().remote_events
    local connections = {}
    for _, remote in ipairs(remotes) do
        local conn = scanner:monitorRemote(remote.instance, callback)
        if conn then connections[#connections + 1] = conn end
    end

    -- Também buscar via game se disponível
    pcall(function()
        local function findRemotes(parent)
            for _, child in ipairs(parent:GetChildren()) do
                if child:IsA("RemoteEvent") then
                    local conn = scanner:monitorRemote(child, callback)
                    if conn then connections[#connections + 1] = conn end
                end
                findRemotes(child)
            end
        end
        findRemotes(game:GetService("ReplicatedStorage"))
    end)

    logger:info("MAIN", string.format("Monitorando %d RemoteEvents", #connections))
    return connections
end

function ScanningLua.logHTTPRequest(method, url, headers, body)
    return networkMonitor:logRequest(method, url, headers, body)
end

function ScanningLua.saveAllResults()
    local timestamp = os.date("!%Y%m%d_%H%M%S")

    -- Logs
    logger:flush(string.format("ScanningLua/logs/scan_log_%s.json", timestamp))

    -- Resultados do scanner
    scanner:saveResults(string.format("ScanningLua/reports/scan_results_%s.json", timestamp))

    -- Relatório de vulnerabilidades
    vulnDetector:saveReport(string.format("ScanningLua/reports/vuln_report_%s.json", timestamp))

    -- Relatório de rede
    local networkData = networkMonitor:exportJSON()
    pcall(function()
        if writefile then
            writefile(string.format("ScanningLua/reports/network_%s.json", timestamp), networkData)
        end
    end)

    logger:info("MAIN", "Todos os resultados salvos em ScanningLua/")
end

function ScanningLua.getVulnerabilityReport()
    return vulnDetector:generateReport()
end

function ScanningLua.getVulnerabilityReportJSON()
    return vulnDetector:exportReportJSON()
end

function ScanningLua.getStats()
    return {
        scanner = scanner:getSummary(),
        vulnerabilities = vulnDetector:getStats(),
        network = networkMonitor:getStats(),
        filters = filters:getStats(),
        logger = logger:getStats(),
    }
end

function ScanningLua.printSummary()
    local stats = ScanningLua.getStats()
    print("\n============================================")
    print("  RESUMO DO SCAN")
    print("============================================")
    print(string.format("  Scripts analisados:      %d", stats.scanner.scripts_analyzed))
    print(string.format("  RemoteEvents:            %d", stats.scanner.remote_events))
    print(string.format("  RemoteFunctions:         %d", stats.scanner.remote_functions))
    print(string.format("  Itens suspeitos:         %d", stats.scanner.suspicious_items))
    print(string.format("  Vulnerabilidades:        %d", stats.vulnerabilities.total_detected))
    print(string.format("    CRITICAL: %d", stats.vulnerabilities.by_severity.CRITICAL))
    print(string.format("    HIGH:     %d", stats.vulnerabilities.by_severity.HIGH))
    print(string.format("    MEDIUM:   %d", stats.vulnerabilities.by_severity.MEDIUM))
    print(string.format("    LOW:      %d", stats.vulnerabilities.by_severity.LOW))
    print(string.format("  Requisições de rede:     %d", stats.network.total_requests))
    print(string.format("  Requisições suspeitas:   %d", stats.network.suspicious_requests))
    print("============================================\n")
end

function ScanningLua.reset()
    scanner:reset()
    vulnDetector:reset()
    networkMonitor:reset()
    filters:reset()
    logger:info("MAIN", "Todos os módulos resetados")
end

function ScanningLua.shutdown()
    logger:info("MAIN", "Encerrando Scanning-Lua...")
    ScanningLua.saveAllResults()
    logger:close()
    print("[Scanning-Lua] Encerrado com sucesso.")
end

-- ================================================================
-- AUTO-EXECUÇÃO: Scan completo ao carregar
-- ================================================================
print("\n[Scanning-Lua] Executando scan completo...")
ScanningLua.fullScan()
ScanningLua.printSummary()

print("[Scanning-Lua] Scanner pronto. Use a API via getgenv().ScanningLua")
print("  Comandos disponíveis:")
print("    ScanningLua.fullScan()         - Scan completo do jogo")
print("    ScanningLua.scanCode(code)     - Analisar código Lua")
print("    ScanningLua.scanScript(inst)   - Analisar um script")
print("    ScanningLua.monitorAllRemotes() - Monitorar RemoteEvents")
print("    ScanningLua.printSummary()     - Ver resumo")
print("    ScanningLua.saveAllResults()   - Salvar relatórios JSON")
print("    ScanningLua.getVulnerabilityReportJSON() - Ver relatório")
print("    ScanningLua.shutdown()         - Encerrar e salvar")

-- Expor globalmente para acesso no executor
pcall(function()
    if getgenv then
        getgenv().ScanningLua = ScanningLua
    end
end)

return ScanningLua
