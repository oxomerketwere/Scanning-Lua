--[[
    ╔══════════════════════════════════════════════════════════════╗
    ║                    Scanning-Lua v3.0.0                      ║
    ║          Scanner de Segurança para Roblox                   ║
    ║                                                              ║
    ║  loadstring(game:HttpGet(                                    ║
    ║    "https://raw.githubusercontent.com/                       ║
    ║     oxomerketwere/Scanning-Lua/main/loader.lua"))()          ║
    ╚══════════════════════════════════════════════════════════════╝
]]

-- ================================================================
-- ANTI-DETECÇÃO: Nomes aleatórios para evitar fingerprinting
-- ================================================================
local function _rnd(n)
    local c = "abcdefghijklmnopqrstuvwxyz"
    local r = {}
    for i = 1, (n or 8) do
        local idx = math.random(1, #c)
        r[i] = c:sub(idx, idx)
    end
    return table.concat(r)
end

-- Nomes internos randomizados a cada execução
local _ID = _rnd(12)
local _TS = os.time()

-- ================================================================
-- MÓDULO: JSON (encoder/decoder completo)
-- ================================================================
local _J = {}
local _ESC = {
    ["\\"]="\\\\", ['"']='\\"', ["\n"]="\\n",
    ["\r"]="\\r", ["\t"]="\\t", ["\b"]="\\b", ["\f"]="\\f",
}

local function _escStr(s)
    return s:gsub('[\\"%c]', function(c)
        return _ESC[c] or string.format("\\u%04x", string.byte(c))
    end)
end

local function _isArr(t)
    local n = 0
    for _ in pairs(t) do n = n + 1 end
    for i = 1, n do if t[i] == nil then return false end end
    return n > 0
end

function _J.encode(v, ind, ci)
    ind = ind or nil; ci = ci or 0
    local tp = type(v)
    if v == nil then return "null"
    elseif tp == "boolean" then return tostring(v)
    elseif tp == "number" then
        if v ~= v or v == math.huge or v == -math.huge then return "null" end
        return tostring(v)
    elseif tp == "string" then return '"'.._escStr(v)..'"'
    elseif tp == "table" then
        local p = {}
        local ni = ci + (ind or 0)
        local sep = ind and ",\n" or ","
        local pad = ind and string.rep(" ", ni) or ""
        local cp = ind and string.rep(" ", ci) or ""
        local col = ind and ": " or ":"
        if _isArr(v) then
            for i = 1, #v do p[#p+1] = pad.._J.encode(v[i], ind, ni) end
            if #p == 0 then return "[]" end
            if ind then return "[\n"..table.concat(p, sep).."\n"..cp.."]"
            else
                local c = {}
                for i = 1, #v do c[#c+1] = _J.encode(v[i], ind, ni) end
                return "["..table.concat(c, ",").."]"
            end
        else
            local ks = {}
            for k in pairs(v) do
                if type(k) == "string" or type(k) == "number" then ks[#ks+1] = k end
            end
            table.sort(ks, function(a,b) return tostring(a)<tostring(b) end)
            for _, k in ipairs(ks) do
                local kk = '"'.._escStr(tostring(k))..'"'
                p[#p+1] = pad..kk..col.._J.encode(v[k], ind, ni)
            end
            if #p == 0 then return "{}" end
            if ind then return "{\n"..table.concat(p, sep).."\n"..cp.."}"
            else
                local c = {}
                for _, k in ipairs(ks) do
                    c[#c+1] = '"'.._escStr(tostring(k))..'":'
                        .._J.encode(v[k], ind, ni)
                end
                return "{"..table.concat(c, ",").."}"
            end
        end
    end
    return "null"
end

function _J.pretty(v, sz) return _J.encode(v, sz or 2, 0) end

function _J.decode(str)
    if type(str) ~= "string" then return nil, "Expected string" end
    local pos = 1
    local function sw() pos = str:find("[^ \t\r\n]", pos) or (#str+1) end
    local function pk() return str:sub(pos, pos) end
    local function eat(e) if str:sub(pos,pos)~=e then return false end; pos=pos+1; return true end
    local pv
    local function ps()
        if not eat('"') then return nil, "Expected '\"'" end
        local r = {}
        while pos <= #str do
            local c = str:sub(pos,pos)
            if c == '"' then pos=pos+1; return table.concat(r)
            elseif c == '\\' then
                pos=pos+1; local e=str:sub(pos,pos)
                if e=='"' then r[#r+1]='"' elseif e=='\\' then r[#r+1]='\\'
                elseif e=='n' then r[#r+1]='\n' elseif e=='r' then r[#r+1]='\r'
                elseif e=='t' then r[#r+1]='\t' elseif e=='/' then r[#r+1]='/'
                elseif e=='u' then
                    local h=str:sub(pos+1,pos+4); local cp=tonumber(h,16)
                    if cp then
                        if cp<128 then r[#r+1]=string.char(cp)
                        elseif cp<2048 then
                            r[#r+1]=string.char(192+math.floor(cp/64), 128+(cp%64))
                        else
                            r[#r+1]=string.char(224+math.floor(cp/4096),
                                128+math.floor((cp%4096)/64), 128+(cp%64))
                        end
                        pos=pos+4
                    end
                end
                pos=pos+1
            else r[#r+1]=c; pos=pos+1 end
        end
        return nil, "Unterminated string"
    end
    local function pn()
        local sp=pos
        if str:sub(pos,pos)=='-' then pos=pos+1 end
        while pos<=#str and str:sub(pos,pos):match("%d") do pos=pos+1 end
        if pos<=#str and str:sub(pos,pos)=='.' then
            pos=pos+1
            while pos<=#str and str:sub(pos,pos):match("%d") do pos=pos+1 end
        end
        if pos<=#str and str:sub(pos,pos):match("[eE]") then
            pos=pos+1
            if pos<=#str and str:sub(pos,pos):match("[%+%-]") then pos=pos+1 end
            while pos<=#str and str:sub(pos,pos):match("%d") do pos=pos+1 end
        end
        return tonumber(str:sub(sp,pos-1))
    end
    local function pa()
        if not eat('[') then return nil end
        local a={}; sw()
        if pk()==']' then pos=pos+1; return a end
        while true do
            sw(); local v,e=pv(); if e then return nil,e end
            a[#a+1]=v; sw(); if not eat(',') then break end
        end
        if not eat(']') then return nil,"Expected ']'" end; return a
    end
    local function po()
        if not eat('{') then return nil end
        local o={}; sw()
        if pk()=='}' then pos=pos+1; return o end
        while true do
            sw(); local k,e=ps(); if e then return nil,e end
            sw(); if not eat(':') then return nil,"Expected ':'" end
            sw(); local v; v,e=pv(); if e then return nil,e end
            o[k]=v; sw(); if not eat(',') then break end
        end
        if not eat('}') then return nil,"Expected '}'" end; return o
    end
    pv = function()
        sw(); local c=pk()
        if c=='"' then return ps()
        elseif c=='{' then return po()
        elseif c=='[' then return pa()
        elseif c=='t' then if str:sub(pos,pos+3)=="true" then pos=pos+4; return true end
        elseif c=='f' then if str:sub(pos,pos+4)=="false" then pos=pos+5; return false end
        elseif c=='n' then if str:sub(pos,pos+3)=="null" then pos=pos+4; return nil end
        elseif c=='-' or (c and c:match("%d")) then return pn()
        end
        return nil, "Unexpected '"..tostring(c).."' at "..pos
    end
    return pv()
end

-- ================================================================
-- MÓDULO: Logger (buffered, anti-detection)
-- ================================================================
local _L = {}; _L.__index = _L
local _LL = { DEBUG=1, INFO=2, WARN=3, ERROR=4, CRITICAL=5 }

function _L.new(minLevel, bufferOutput)
    local self = setmetatable({}, _L)
    self.min = _LL[minLevel] or _LL.INFO
    self.entries = {}
    self.count = 0
    self.sid = _ID
    self.start = _TS
    self.buffer = bufferOutput or false -- Anti-detecção: não printar imediatamente
    self.pendingPrints = {}
    return self
end

function _L:_ts() return os.date("!%Y-%m-%dT%H:%M:%SZ") end

function _L:_add(level, cat, msg, data)
    local lv = _LL[level]
    if not lv or lv < self.min then return end
    self.count = self.count + 1
    local e = {
        id = self.count, timestamp = self:_ts(), level = level,
        category = cat, message = msg, session = self.sid,
    }
    if data then e.data = data end
    if (level == "ERROR" or level == "CRITICAL") and debug and debug.traceback then
        e.stack = debug.traceback("", 3)
    end
    self.entries[#self.entries + 1] = e

    -- Anti-detecção: buffered output
    local line = string.format("[%s][%s][%s] %s", e.timestamp, level, cat, msg)
    if self.buffer then
        self.pendingPrints[#self.pendingPrints + 1] = line
    else
        print(line)
    end
    return e
end

function _L:flushPrints()
    for _, line in ipairs(self.pendingPrints) do print(line) end
    self.pendingPrints = {}
end

function _L:debug(c, m, d) return self:_add("DEBUG", c, m, d) end
function _L:info(c, m, d) return self:_add("INFO", c, m, d) end
function _L:warn(c, m, d) return self:_add("WARN", c, m, d) end
function _L:error(c, m, d) return self:_add("ERROR", c, m, d) end
function _L:critical(c, m, d) return self:_add("CRITICAL", c, m, d) end

function _L:save(filename)
    if #self.entries == 0 then return true end
    local data = {
        metadata = {
            session_id = self.sid, start_time = os.date("!%Y-%m-%dT%H:%M:%SZ", self.start),
            version = "2.0.0",
        },
        total_entries = #self.entries, entries = self.entries,
    }
    local json = _J.pretty(data)
    local ok = false
    -- writefile (Roblox executors)
    pcall(function()
        if writefile then writefile(filename, json); ok = true end
    end)
    -- Fallback: io.open
    if not ok then
        pcall(function()
            local f = io.open(filename, "w")
            if f then f:write(json); f:close(); ok = true end
        end)
    end
    if ok then self.entries = {}; self.count = 0 end
    return ok
end

function _L:toJSON()
    return _J.pretty({
        metadata = { session_id = self.sid, version = "2.0.0" },
        total_entries = #self.entries, entries = self.entries,
    })
end

function _L:getStats()
    local s = { total = #self.entries, by_level = { DEBUG=0, INFO=0, WARN=0, ERROR=0, CRITICAL=0 } }
    for _, e in ipairs(self.entries) do s.by_level[e.level] = (s.by_level[e.level] or 0) + 1 end
    return s
end

-- ================================================================
-- 🔥 MÓDULO: Risk Score Engine (ANÁLISE CONTEXTUAL)
-- ================================================================
local _RS = {}; _RS.__index = _RS

-- Pesos de risco por tipo de padrão
local RISK_WEIGHTS = {
    -- Execução dinâmica (peso alto)
    loadstring = 8,
    -- Rede
    HttpGet = 4, HttpPost = 4,
    ["syn%.request"] = 5, http_request = 5, request = 3,
    -- Metatable/hooking (crítico)
    getrawmetatable = 7, setrawmetatable = 9,
    hookfunction = 9, hookmetamethod = 9,
    -- Ambiente
    getgenv = 5, getrenv = 5, getfenv = 6, setfenv = 8,
    -- Debug
    ["debug%.getupvalue"] = 4, ["debug%.setupvalue"] = 7,
    ["debug%.getinfo"] = 3, ["debug%.getconstant"] = 4,
    ["debug%.setconstant"] = 7,
    -- Namecall
    getnamecallmethod = 5, setnamecallmethod = 6,
    newcclosure = 5,
    -- Input simulation
    firesignal = 4, fireserver = 5,
    fireclickdetector = 3, firetouchinterest = 3, fireproximityprompt = 3,
    -- Outros
    GetObjects = 3,
    ["require%((%d+)%)"] = 4,
}

-- Combinações perigosas (multiplicadores)
local RISK_COMBOS = {
    { patterns = { "loadstring", "HttpGet" },       multiplier = 2.5, name = "Remote Code Execution" },
    { patterns = { "loadstring", "HttpPost" },      multiplier = 2.5, name = "Remote Code Execution" },
    { patterns = { "getrawmetatable", "hookfunction" }, multiplier = 2.0, name = "Full Environment Hijack" },
    { patterns = { "getrawmetatable", "setrawmetatable" }, multiplier = 2.0, name = "Metatable Takeover" },
    { patterns = { "getnamecallmethod", "setnamecallmethod" }, multiplier = 1.8, name = "Namecall Hijack" },
    { patterns = { "getgenv", "hookfunction" },     multiplier = 1.8, name = "Global Hook Injection" },
    { patterns = { "getrenv", "hookfunction" },     multiplier = 1.8, name = "Registry Hook Injection" },
    { patterns = { "HttpGet", "getgenv" },          multiplier = 1.5, name = "Remote Data to Global" },
    { patterns = { "debug%.setupvalue", "getfenv" }, multiplier = 2.0, name = "Upvalue + Env Manipulation" },
    { patterns = { "fireserver", "getrawmetatable" }, multiplier = 1.7, name = "Spoofed Server Call" },
    { patterns = { "syn%.request", "getgenv" },     multiplier = 1.6, name = "Exfiltration via Request" },
}

function _RS.new(logger)
    local self = setmetatable({}, _RS)
    self.logger = logger
    self.analyses = {}
    return self
end

--- Remove comentários para análise limpa
local function _stripComments(code)
    code = code:gsub("%-%-%[%[.-%]%]", "")   -- bloco
    code = code:gsub("%-%-[^\n]*", "")         -- linha
    return code
end

--- Analisa código com score de risco contextual
--- @param code string Código a analisar
--- @param source string Identificador
--- @return table Análise completa com score
function _RS:analyze(code, source)
    if type(code) ~= "string" then
        return { score = 0, level = "NONE", findings = {} }
    end

    source = source or "unknown"
    local clean = _stripComments(code)
    local score = 0
    local findings = {}
    local foundPatterns = {}

    -- 1. Detectar padrões individuais e somar pesos
    for pattern, weight in pairs(RISK_WEIGHTS) do
        local searchStart = 1
        local matchCount = 0
        while true do
            local ms, me = clean:find(pattern, searchStart)
            if not ms then break end
            matchCount = matchCount + 1
            searchStart = me + 1
        end
        if matchCount > 0 then
            -- Peso diminui após 3 ocorrências (não contar spam)
            local effectiveWeight = weight * math.min(matchCount, 3)
            score = score + effectiveWeight
            foundPatterns[pattern] = matchCount

            -- Extrair linha
            local lineNum = 1
            local firstPos = clean:find(pattern)
            if firstPos then
                for _ in clean:sub(1, firstPos):gmatch("\n") do lineNum = lineNum + 1 end
            end

            findings[#findings + 1] = {
                pattern = pattern,
                count = matchCount,
                weight = weight,
                effective_weight = effectiveWeight,
                line = lineNum,
                severity = weight >= 7 and "CRITICAL" or (weight >= 5 and "HIGH" or (weight >= 3 and "MEDIUM" or "LOW")),
            }
        end
    end

    -- 2. Verificar combinações perigosas (multiplicadores)
    local combosFound = {}
    for _, combo in ipairs(RISK_COMBOS) do
        local allPresent = true
        for _, pat in ipairs(combo.patterns) do
            if not foundPatterns[pat] then
                allPresent = false
                break
            end
        end
        if allPresent then
            score = score * combo.multiplier
            combosFound[#combosFound + 1] = {
                name = combo.name,
                patterns = combo.patterns,
                multiplier = combo.multiplier,
            }
        end
    end

    -- 3. Bonus por ofuscação (analisado separadamente mas impacta score)
    local obfScore = self:_quickObfuscationScore(clean)
    if obfScore > 0 then
        score = score + obfScore
        findings[#findings + 1] = {
            pattern = "_OBFUSCATION_",
            count = 1,
            weight = obfScore,
            effective_weight = obfScore,
            severity = obfScore >= 15 and "CRITICAL" or (obfScore >= 8 and "HIGH" or "MEDIUM"),
        }
    end

    -- 4. Calcular nível
    local level = "NONE"
    if score >= 50 then level = "CRITICAL"
    elseif score >= 25 then level = "HIGH"
    elseif score >= 10 then level = "MEDIUM"
    elseif score > 0 then level = "LOW"
    end

    local result = {
        source = source,
        score = math.floor(score * 100) / 100, -- 2 decimais
        level = level,
        findings = findings,
        combos = combosFound,
        patterns_found = foundPatterns,
        code_length = #code,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    }

    self.analyses[#self.analyses + 1] = result

    if self.logger then
        local emoji = level == "CRITICAL" and "🔴" or
            (level == "HIGH" and "🟠" or (level == "MEDIUM" and "🟡" or "🟢"))
        self.logger:info("RISK", string.format(
            "%s [%s] Score: %.1f | %d padrões | %d combos | %s",
            emoji, level, score, #findings, #combosFound, source
        ), { score = result.score, level = level })
    end

    return result
end

--- Score rápido de ofuscação (para compor o risk score)
function _RS:_quickObfuscationScore(code)
    local s = 0
    -- Muitas concatenações
    local concats = 0
    for _ in code:gmatch("%.%.") do concats = concats + 1 end
    if concats > 20 then s = s + 5 end

    -- Hex encoding
    local hexCount = 0
    for _ in code:gmatch("\\x%x%x") do hexCount = hexCount + 1 end
    if hexCount > 10 then s = s + 6 end

    -- Base64
    for str in code:gmatch('"([^"]+)"') do
        if #str > 200 and str:match("^[A-Za-z0-9+/=]+$") then
            s = s + 8
            break
        end
    end

    -- Ofuscadores conhecidos
    local obfPatterns = {
        "IIlIIlIIlIlI", "LPH_", "PSU_", "Moonsec",
        "IllIllIllI", "ILIIILIIIL",
    }
    for _, p in ipairs(obfPatterns) do
        if code:find(p, 1, true) then s = s + 15; break end
    end

    -- String.char em massa
    local scharCount = 0
    for _ in code:gmatch("string%.char") do scharCount = scharCount + 1 end
    if scharCount > 5 then s = s + 5 end

    -- Linhas gigantes (minificação)
    for line in code:gmatch("[^\n]+") do
        if #line > 1000 then s = s + 4; break end
    end

    -- Poucas linhas, muito código
    local lines = 0
    for _ in code:gmatch("\n") do lines = lines + 1 end
    if lines < 10 and #code > 5000 then s = s + 6 end

    return s
end

function _RS:getAnalyses() return self.analyses end

-- ================================================================
-- 🧠 MÓDULO: Obfuscation Detector (COMPLETO)
-- ================================================================
local _OD = {}; _OD.__index = _OD

function _OD.new(logger)
    local self = setmetatable({}, _OD)
    self.logger = logger
    self.detections = {}
    self.stats = { total = 0, detected = 0, by_technique = {} }
    return self
end

function _OD:analyze(code, source)
    if type(code) ~= "string" then return {} end
    self.stats.total = self.stats.total + 1
    source = source or "unknown"
    local dets = {}

    self:_concatEvasion(code, source, dets)
    self:_stringEncoding(code, source, dets)
    self:_base64Detection(code, source, dets)
    self:_minification(code, source, dets)
    self:_knownObfuscators(code, source, dets)
    self:_stringCharConstruction(code, source, dets)
    self:_tableConcat(code, source, dets)
    self:_antiDecompile(code, source, dets)
    self:_highEntropy(code, source, dets)
    self:_variableObfuscation(code, source, dets)

    if #dets > 0 then
        self.stats.detected = self.stats.detected + #dets
        self.detections[#self.detections + 1] = {
            source = source, detections = dets, timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
        if self.logger then
            self.logger:warn("OBFUSC", string.format(
                "🧠 %d técnicas de ofuscação em %s", #dets, source
            ))
        end
    end
    return dets
end

function _OD:_addDet(dets, tech, sev, desc, extra)
    local d = { technique = tech, severity = sev, description = desc }
    if extra then for k, v in pairs(extra) do d[k] = v end end
    dets[#dets + 1] = d
    self.stats.by_technique[tech] = (self.stats.by_technique[tech] or 0) + 1
end

function _OD:_concatEvasion(code, source, dets)
    local splits = {
        { {"load","string"}, "loadstring" },
        { {"Http","Get"}, "HttpGet" },
        { {"Http","Post"}, "HttpPost" },
        { {"get","raw","metatable"}, "getrawmetatable" },
        { {"set","raw","metatable"}, "setrawmetatable" },
        { {"hook","function"}, "hookfunction" },
        { {"get","genv"}, "getgenv" },
        { {"fire","server"}, "fireserver" },
    }
    for _, entry in ipairs(splits) do
        local parts, keyword = entry[1], entry[2]
        -- Procurar: "part1" .. "part2"
        local pat = ""
        for i, p in ipairs(parts) do
            if i > 1 then pat = pat .. "[\"']%s*%.%.%s*[\"']" end
            pat = pat .. p
        end
        if code:find(pat) then
            self:_addDet(dets, "STRING_CONCAT_EVASION", "HIGH",
                string.format("Evasão via concatenação para '%s'", keyword),
                { evaded_keyword = keyword })
        end
    end
    -- Concatenações excessivas numa linha
    for line in code:gmatch("[^\n]+") do
        local cnt = 0
        for _ in line:gmatch("%.%.") do cnt = cnt + 1 end
        if cnt >= 8 then
            self:_addDet(dets, "EXCESSIVE_CONCAT", "MEDIUM",
                string.format("Linha com %d concatenações", cnt), { count = cnt })
            break
        end
    end
end

function _OD:_stringEncoding(code, source, dets)
    local hx = 0
    for _ in code:gmatch("\\x%x%x") do hx = hx + 1 end
    if hx >= 10 then
        self:_addDet(dets, "HEX_ENCODING", "HIGH",
            string.format("%d sequências hex", hx), { count = hx })
    end
    local oct = 0
    for _ in code:gmatch("\\%d%d%d") do oct = oct + 1 end
    if oct >= 10 then
        self:_addDet(dets, "OCTAL_ENCODING", "HIGH",
            string.format("%d sequências octal", oct), { count = oct })
    end
end

function _OD:_base64Detection(code, source, dets)
    for str in code:gmatch('"([^"]+)"') do
        if #str > 200 and str:match("^[A-Za-z0-9+/=]+$") then
            self:_addDet(dets, "BASE64_PAYLOAD", "CRITICAL",
                string.format("String Base64 de %d chars detectada", #str),
                { length = #str })
            break
        end
    end
    for str in code:gmatch("'([^']+)'") do
        if #str > 200 and str:match("^[A-Za-z0-9+/=]+$") then
            self:_addDet(dets, "BASE64_PAYLOAD", "CRITICAL",
                string.format("String Base64 de %d chars detectada", #str),
                { length = #str })
            break
        end
    end
end

function _OD:_minification(code, source, dets)
    local lines = {}
    for line in code:gmatch("[^\n]+") do lines[#lines+1] = line end
    if #lines == 0 then return end
    local longLines = 0
    for _, l in ipairs(lines) do if #l > 500 then longLines = longLines + 1 end end
    local avg = #code / math.max(#lines, 1)
    if longLines >= 3 or (avg > 200 and #lines < 15 and #code > 3000) then
        self:_addDet(dets, "MINIFICATION", "MEDIUM",
            string.format("Código minificado (%d linhas, avg %d chars)", #lines, math.floor(avg)),
            { total_lines = #lines, avg_length = math.floor(avg) })
    end
    -- Variáveis de uma letra
    local sv = 0
    for _ in code:gmatch("local%s+[a-z]%s*=") do sv = sv + 1 end
    if sv >= 20 then
        self:_addDet(dets, "MINIFIED_VARS", "LOW",
            string.format("%d variáveis de uma letra", sv), { count = sv })
    end
end

function _OD:_knownObfuscators(code, source, dets)
    local obfs = {
        { "IIlIIlIIlIlI", "Luraph" }, { "LPH_", "Luraph" },
        { "PSU_", "PSU" }, { "Moonsec", "Moonsec" },
        { "IllIllIllI", "Generic IL" }, { "ILIIILIIIL", "IronBrew" },
        { "xor_key", "XOR Obfuscator" }, { "Bytecode", "Bytecode Obf" },
    }
    for _, o in ipairs(obfs) do
        if code:find(o[1], 1, true) then
            self:_addDet(dets, "KNOWN_OBFUSCATOR", "CRITICAL",
                string.format("Ofuscador detectado: %s", o[2]),
                { obfuscator = o[2], marker = o[1] })
        end
    end
end

function _OD:_stringCharConstruction(code, source, dets)
    local cnt = 0
    for _ in code:gmatch("string%.char") do cnt = cnt + 1 end
    if cnt >= 5 then
        self:_addDet(dets, "STRING_CHAR_BUILD", "HIGH",
            string.format("%d usos de string.char - payload char-by-char", cnt), { count = cnt })
    end
end

function _OD:_tableConcat(code, source, dets)
    local cnt = 0
    for _ in code:gmatch("table%.concat") do cnt = cnt + 1 end
    if cnt >= 3 then
        self:_addDet(dets, "TABLE_CONCAT_BUILD", "MEDIUM",
            string.format("%d usos de table.concat", cnt), { count = cnt })
    end
end

function _OD:_antiDecompile(code, source, dets)
    local aps = {
        { "string%.dump", "Bytecode dumping" },
        { "setfenv.*0", "Environment level 0" },
        { "coroutine%.wrap.*coroutine%.yield", "Coroutine confusion" },
    }
    for _, ap in ipairs(aps) do
        if code:find(ap[1]) then
            self:_addDet(dets, "ANTI_DECOMPILE", "HIGH",
                "Anti-decompile: "..ap[2], { method = ap[2] })
        end
    end
end

function _OD:_highEntropy(code, source, dets)
    for str in code:gmatch('"([^"]+)"') do
        if #str >= 100 then
            local freq = {}
            for i = 1, #str do freq[str:sub(i,i)] = true end
            local uniq = 0
            for _ in pairs(freq) do uniq = uniq + 1 end
            if uniq > 50 and (uniq / #str) > 0.3 then
                self:_addDet(dets, "HIGH_ENTROPY", "MEDIUM",
                    string.format("String alta entropia (%d chars, %d únicos)", #str, uniq),
                    { length = #str, unique = uniq })
                break
            end
        end
    end
end

function _OD:_variableObfuscation(code, source, dets)
    -- Detectar nomes de variáveis com padrões I/l misturados
    local ilCount = 0
    for name in code:gmatch("local%s+([IlO0]+)%s*=") do
        if #name >= 4 then ilCount = ilCount + 1 end
    end
    if ilCount >= 3 then
        self:_addDet(dets, "IL_VAR_OBFUSCATION", "HIGH",
            string.format("%d variáveis com nomes I/l ofuscados", ilCount),
            { count = ilCount })
    end
end

function _OD:getStats() return self.stats end
function _OD:getDetections() return self.detections end
function _OD:reset()
    self.detections = {}
    self.stats = { total = 0, detected = 0, by_technique = {} }
end

-- ================================================================
-- 🌐 MÓDULO: Network Monitor (AVANÇADO)
-- ================================================================
local _NM = {}; _NM.__index = _NM

-- Domínios de risco conhecidos
local RISK_DOMAINS = {
    ["pastebin.com"] = { risk = 7, reason = "Hosting de payloads" },
    ["raw.githubusercontent.com"] = { risk = 5, reason = "Raw script hosting" },
    ["hastebin.com"] = { risk = 6, reason = "Paste service" },
    ["paste.ee"] = { risk = 6, reason = "Paste service" },
    ["rentry.co"] = { risk = 5, reason = "Paste service" },
    ["discord.com"] = { risk = 4, reason = "Webhook exfiltration" },
    ["discordapp.com"] = { risk = 4, reason = "Webhook exfiltration" },
    ["discord.gg"] = { risk = 3, reason = "Invite link" },
    ["cdn.discordapp.com"] = { risk = 5, reason = "CDN payload hosting" },
    ["repl.it"] = { risk = 5, reason = "Code hosting" },
    ["glitch.me"] = { risk = 5, reason = "App hosting" },
    ["herokuapp.com"] = { risk = 5, reason = "App hosting" },
    ["ngrok.io"] = { risk = 8, reason = "Tunnel (C2 potencial)" },
    ["webhook.site"] = { risk = 7, reason = "Webhook testing/exfil" },
    ["requestbin.com"] = { risk = 7, reason = "Request logging" },
    ["iplogger.org"] = { risk = 9, reason = "IP grabber" },
    ["grabify.link"] = { risk = 9, reason = "IP grabber" },
}

-- Domínios seguros (whitelist)
local SAFE_DOMAINS = {
    "roblox.com", "rbxcdn.com", "robloxcdn.com", "rbx.com",
}

function _NM.new(logger)
    local self = setmetatable({}, _NM)
    self.logger = logger
    self.requests = {}
    self.blocked = {}
    self.hooks = {}
    self.stats = {
        total = 0, suspicious = 0, blocked = 0,
        by_method = {}, by_domain = {},
    }
    -- Detecção de comportamento
    self.domainTimestamps = {} -- timestamps por domínio para rate detection
    self.burstThreshold = 10  -- requests em 5 segundos = burst
    return self
end

--- Parser de URL completo
--- @param url string URL
--- @return table Componentes parsed
function _NM.parseURL(url)
    if type(url) ~= "string" then return { raw = tostring(url) } end
    local result = { raw = url }

    -- Protocolo
    result.protocol = url:match("^(https?)://") or "unknown"

    -- Domínio e porta
    local hostPort = url:match("^https?://([^/]+)") or url:match("^([^/]+)")
    if hostPort then
        result.host = hostPort:match("^([^:]+)")
        result.port = tonumber(hostPort:match(":(%d+)$"))
    end

    -- Path
    result.path = url:match("^https?://[^/]+(/.-)%?") or url:match("^https?://[^/]+(/[^?#]*)") or "/"

    -- Query string
    local qs = url:match("%?([^#]+)")
    if qs then
        result.query_string = qs
        result.query = {}
        for k, v in qs:gmatch("([^&=]+)=([^&]*)") do
            result.query[k] = v
        end
    end

    -- Fragment
    result.fragment = url:match("#(.+)$")

    -- Extrair domínio base (sem subdomínios)
    if result.host then
        local parts = {}
        for part in result.host:gmatch("[^.]+") do parts[#parts + 1] = part end
        if #parts >= 2 then
            result.base_domain = parts[#parts - 1] .. "." .. parts[#parts]
        else
            result.base_domain = result.host
        end
    end

    return result
end

--- Verifica se domínio é seguro
function _NM:isSafe(domain)
    if not domain then return false end
    domain = domain:lower()
    for _, safe in ipairs(SAFE_DOMAINS) do
        if domain == safe or domain:match("%." .. safe:gsub("%.", "%%.") .. "$") then
            return true
        end
    end
    return false
end

--- Obtém risco de um domínio
function _NM:getDomainRisk(domain)
    if not domain then return { risk = 5, reason = "Domínio desconhecido" } end
    domain = domain:lower()
    -- Checar exato
    if RISK_DOMAINS[domain] then return RISK_DOMAINS[domain] end
    -- Checar base domain
    local parts = {}
    for p in domain:gmatch("[^.]+") do parts[#parts+1] = p end
    if #parts >= 2 then
        local base = parts[#parts-1].."."..parts[#parts]
        if RISK_DOMAINS[base] then return RISK_DOMAINS[base] end
    end
    -- Whitelist
    if self:isSafe(domain) then return { risk = 0, reason = "Domínio confiável" } end
    return { risk = 3, reason = "Domínio não catalogado" }
end

--- Detecta burst de requests (comportamento suspeito)
function _NM:_detectBurst(domain)
    local now = os.time()
    if not self.domainTimestamps[domain] then
        self.domainTimestamps[domain] = {}
    end
    local ts = self.domainTimestamps[domain]
    ts[#ts + 1] = now
    -- Limpar timestamps antigos (> 10s)
    local recent = {}
    for _, t in ipairs(ts) do
        if now - t <= 10 then recent[#recent + 1] = t end
    end
    self.domainTimestamps[domain] = recent
    return #recent >= self.burstThreshold
end

--- Registra uma requisição HTTP
function _NM:logRequest(method, url, headers, body)
    local parsed = _NM.parseURL(url)
    local domain = parsed.host
    local isSafe = self:isSafe(domain)
    local domainRisk = self:getDomainRisk(domain)
    local isBurst = self:_detectBurst(domain or "unknown")

    local entry = {
        id = #self.requests + 1,
        method = method or "UNKNOWN",
        url = url,
        parsed = parsed,
        domain = domain,
        domain_risk = domainRisk,
        is_safe = isSafe,
        is_suspicious = not isSafe or domainRisk.risk >= 5,
        is_burst = isBurst,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        body_size = (type(body) == "string") and #body or 0,
    }

    self.requests[#self.requests + 1] = entry
    self.stats.total = self.stats.total + 1
    self.stats.by_method[method] = (self.stats.by_method[method] or 0) + 1
    self.stats.by_domain[domain or "unknown"] = (self.stats.by_domain[domain or "unknown"] or 0) + 1

    if entry.is_suspicious then
        self.stats.suspicious = self.stats.suspicious + 1
        self.blocked[#self.blocked + 1] = entry
    end

    if isBurst then
        if self.logger then
            self.logger:critical("NETWORK", string.format(
                "⚡ BURST detectado: %d requests para %s em 10s",
                #(self.domainTimestamps[domain or "unknown"] or {}), domain or "unknown"
            ), entry)
        end
    elseif entry.is_suspicious and self.logger then
        self.logger:warn("NETWORK", string.format(
            "🌐 Suspeito: %s %s [risco: %d - %s]",
            method, url, domainRisk.risk, domainRisk.reason
        ), entry)
    end

    return entry
end

--- Instala hooks de rede
function _NM:installHooks()
    if self.logger then self.logger:info("NETWORK", "Instalando hooks de rede") end
    local ref = self

    pcall(function()
        if hookfunction and game and game.HttpGet then
            local orig = hookfunction(game.HttpGet, function(g, url, ...)
                ref:logRequest("GET", url)
                return orig(g, url, ...)
            end)
            ref.hooks.httpGet = orig
        end
    end)
    pcall(function()
        if hookfunction and game and game.HttpPost then
            local orig = hookfunction(game.HttpPost, function(g, url, body, ...)
                ref:logRequest("POST", url, nil, body)
                return orig(g, url, body, ...)
            end)
            ref.hooks.httpPost = orig
        end
    end)
    pcall(function()
        local fn = (syn and syn.request) or http_request or request
        if hookfunction and fn then
            local orig = hookfunction(fn, function(opts, ...)
                local m = opts and opts.Method or "GET"
                local u = opts and opts.Url or "unknown"
                local b = opts and opts.Body
                ref:logRequest(m, u, nil, b)
                return orig(opts, ...)
            end)
            ref.hooks.request = orig
        end
    end)
end

--- Análise de tráfego
function _NM:analyzeTraffic()
    local alerts = {}
    for domain, count in pairs(self.stats.by_domain) do
        local risk = self:getDomainRisk(domain)
        if risk.risk >= 5 then
            alerts[#alerts + 1] = {
                type = "RISKY_DOMAIN", domain = domain,
                risk_score = risk.risk, reason = risk.reason,
                request_count = count, severity = risk.risk >= 7 and "HIGH" or "MEDIUM",
            }
        end
    end
    if self.stats.total > 50 then
        alerts[#alerts + 1] = {
            type = "HIGH_VOLUME", total = self.stats.total,
            severity = "MEDIUM",
        }
    end
    return alerts
end

function _NM:getStats() return self.stats end
function _NM:getRequests() return self.requests end
function _NM:exportJSON() return _J.pretty({
    stats = self.stats, alerts = self:analyzeTraffic(),
    requests = self.requests, blocked = self.blocked,
}) end
function _NM:reset()
    self.requests = {}; self.blocked = {}; self.domainTimestamps = {}
    self.stats = { total=0, suspicious=0, blocked=0, by_method={}, by_domain={} }
end

-- ================================================================
-- 🧬 MÓDULO: Environment Fingerprinter
-- ================================================================
local _EF = {}; _EF.__index = _EF

function _EF.new(logger)
    local self = setmetatable({}, _EF)
    self.logger = logger
    self.result = {}
    return self
end

function _EF:scan()
    if self.logger then self.logger:info("ENV", "🧬 Fingerprinting ambiente") end

    self.result = {
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        executor = self:_detectExecutor(),
        lua = { version = _VERSION or "?", jit = jit and jit.version or nil },
        capabilities = self:_scanCaps(),
        risk = {},
    }
    self.result.risk = self:_assess()

    if self.logger then
        self.logger:info("ENV", string.format(
            "🧬 Executor: %s | %d caps | Risco: %s",
            self.result.executor.name,
            self.result.capabilities.total,
            self.result.risk.level
        ))
    end
    return self.result
end

function _EF:_detectExecutor()
    local ex = { name = "Unknown", version = "?" }
    -- Tentar identificar
    local checks = {
        function()
            if identifyexecutor then ex.name = identifyexecutor(); return true end
        end,
        function()
            if getexecutorname then ex.name = getexecutorname(); return true end
        end,
        function()
            if syn and syn.protect_gui then ex.name = "Synapse X"; return true end
        end,
        function()
            if wave or Wave then ex.name = "Wave"; return true end
        end,
        function()
            if KRNL_LOADED then ex.name = "KRNL"; return true end
        end,
        function()
            if fluxus or FLUXUS_FOLDER then ex.name = "Fluxus"; return true end
        end,
        function()
            if Electron then ex.name = "Electron"; return true end
        end,
        function()
            if SW_LOADED then ex.name = "Script-Ware"; return true end
        end,
    }
    for _, check in ipairs(checks) do
        local ok = pcall(check)
        if ok and ex.name ~= "Unknown" then break end
    end
    -- Plataforma
    pcall(function()
        if game and game.PlaceId then
            ex.platform = "Roblox"
            ex.place_id = game.PlaceId
            ex.game_id = game.GameId
        end
    end)
    if ex.name == "Unknown" and not pcall(function() return game end) then
        ex.name = "Lua Standalone"
        ex.platform = "Desktop"
    end
    return ex
end

function _EF:_scanCaps()
    local c = { total = 0, fs = {}, hook = {}, dbg = {}, net = {}, exec = {}, misc = {} }
    local function chk(name, cat)
        local exists = false
        pcall(function()
            if name:find("%.") then
                local a, b = name:match("^(.+)%.(.+)$")
                exists = type(_G[a][b]) == "function"
            else
                exists = type(_G[name]) == "function"
            end
        end)
        if exists then c[cat][#c[cat]+1] = name; c.total = c.total + 1 end
    end
    -- Filesystem
    for _, f in ipairs({"readfile","writefile","appendfile","listfiles","isfile","isfolder","makefolder","delfile","delfolder"}) do
        chk(f, "fs")
    end
    -- Hooking
    for _, f in ipairs({"hookfunction","hookmetamethod","newcclosure","replaceclosure","clonefunction","getnamecallmethod","setnamecallmethod"}) do
        chk(f, "hook")
    end
    -- Debug
    for _, f in ipairs({"debug.getupvalue","debug.setupvalue","debug.getinfo","debug.getconstant","debug.setconstant","debug.getregistry"}) do
        chk(f, "dbg")
    end
    -- Network
    for _, f in ipairs({"request","http_request"}) do chk(f, "net") end
    -- Execution
    for _, f in ipairs({"loadstring","getgenv","getrenv","getfenv","setfenv","getrawmetatable","setrawmetatable","setreadonly","decompile","saveinstance"}) do
        chk(f, "exec")
    end
    -- Misc
    for _, f in ipairs({"fireclickdetector","firetouchinterest","fireproximityprompt","firesignal","getconnections","getinstances","getnilinstances","getscripts","getrunningscripts","getloadedmodules","getreg","getgc","getthreadidentity","setthreadidentity"}) do
        chk(f, "misc")
    end
    return c
end

function _EF:_assess()
    local score = 0
    local c = self.result.capabilities or {}
    if c.hook and #c.hook > 0 then score = score + #c.hook * 5 end
    if c.dbg and #c.dbg > 0 then score = score + #c.dbg * 4 end
    if c.exec and #c.exec > 3 then score = score + #c.exec * 5 end
    if c.fs and #c.fs > 0 then score = score + #c.fs * 2 end
    if c.misc and #c.misc > 3 then score = score + #c.misc * 2 end
    local level = score >= 80 and "CRITICAL" or (score >= 50 and "HIGH" or (score >= 25 and "MEDIUM" or "LOW"))
    return { level = level, score = score }
end

function _EF:getResult() return self.result end

-- ================================================================
-- 🕵️ MÓDULO: Anti-Detection
-- ================================================================
local _AD = {}; _AD.__index = _AD

function _AD.new(logger)
    local self = setmetatable({}, _AD)
    self.logger = logger
    self.active = false
    return self
end

function _AD:enable()
    -- 1. Delay aleatório na execução
    pcall(function()
        if task and task.wait then
            task.wait(math.random() * 0.5)
        elseif wait then
            wait(math.random() * 0.3)
        end
    end)

    -- 2. Não expor nada em _G diretamente (já feito: tudo local)
    -- 3. Evitar nomes óbvios (já feito: nomes _J, _L, _RS etc)

    self.active = true
    if self.logger then
        self.logger:debug("STEALTH", "Proteções anti-detecção ativas")
    end
end

--- Verificação de integridade
function _AD:integrityCheck()
    local checks = {}
    -- Verificar se print não foi hookado
    pcall(function()
        if iscclosure then
            checks.print_original = iscclosure(print)
        end
    end)
    -- Verificar tempo (anti-speedhack)
    pcall(function()
        local t = os.time()
        checks.time_valid = type(t) == "number" and t > 1600000000
    end)
    return checks
end

-- ================================================================
-- 📡 MÓDULO: Discord Webhook
-- ================================================================
local _DW = {}; _DW.__index = _DW

function _DW.new(url, logger)
    local self = setmetatable({}, _DW)
    self.url = url
    self.logger = logger
    self.enabled = url ~= nil and url ~= ""
    self.sent = 0
    return self
end

function _DW:setUrl(url) self.url = url; self.enabled = url ~= nil and url ~= "" end

function _DW:_send(payload)
    if not self.enabled then return false end
    local body = _J.encode(payload)
    local ok = false
    -- Tentar múltiplos métodos de request
    pcall(function()
        if syn and syn.request then
            syn.request({ Url=self.url, Method="POST", Headers={["Content-Type"]="application/json"}, Body=body })
            ok = true
        end
    end)
    if not ok then pcall(function()
        if http_request then
            http_request({ Url=self.url, Method="POST", Headers={["Content-Type"]="application/json"}, Body=body })
            ok = true
        end
    end) end
    if not ok then pcall(function()
        if request then
            request({ Url=self.url, Method="POST", Headers={["Content-Type"]="application/json"}, Body=body })
            ok = true
        end
    end) end
    if not ok then pcall(function()
        if game then
            game:GetService("HttpService"):PostAsync(self.url, body)
            ok = true
        end
    end) end
    if ok then self.sent = self.sent + 1 end
    return ok
end

function _DW:sendAlert(vuln)
    if not self.enabled then return false end
    local colors = { CRITICAL=15158332, HIGH=15105570, MEDIUM=16776960, LOW=3447003 }
    return self:_send({ embeds = {{ title="🔒 Vulnerabilidade", color=colors[vuln.severity] or 8421504, fields={
        {name="ID",value=vuln.vuln_id or "N/A",inline=true},
        {name="Severidade",value=vuln.severity or "?",inline=true},
        {name="Score",value=tostring(vuln.score or "?"),inline=true},
        {name="Nome",value=vuln.name or "N/A",inline=false},
        {name="Origem",value=vuln.source or "?",inline=true},
        {name="Descrição",value=(vuln.description or ""):sub(1,200),inline=false},
    }, timestamp=os.date("!%Y-%m-%dT%H:%M:%SZ"), footer={text="Scanning-Lua v2.0.0"} }} })
end

function _DW:sendSummary(summary)
    if not self.enabled then return false end
    local vs = summary.vulnerability_stats or {}
    local sev = vs.by_severity or {}
    local sr = summary.scan_results or {}
    local emoji = (sev.CRITICAL or 0)>0 and "🔴" or ((sev.HIGH or 0)>0 and "🟠" or ((sev.MEDIUM or 0)>0 and "🟡" or "🟢"))
    return self:_send({ embeds = {{ title=emoji.." Scan Completo", color=3447003, fields={
        {name="Scripts",value=tostring(sr.scripts_analyzed or 0),inline=true},
        {name="Remotes",value=tostring((sr.remote_events or 0)+(sr.remote_functions or 0)),inline=true},
        {name="Suspeitos",value=tostring(sr.suspicious_items or 0),inline=true},
        {name="Vulnerabilidades",value=tostring(vs.total_detected or 0),inline=true},
        {name="CRITICAL",value=tostring(sev.CRITICAL or 0),inline=true},
        {name="HIGH",value=tostring(sev.HIGH or 0),inline=true},
        {name="Risk Score",value=tostring(summary.total_risk_score or 0),inline=true},
    }, timestamp=os.date("!%Y-%m-%dT%H:%M:%SZ"), footer={text="Scanning-Lua v2.0.0"} }} })
end

-- ================================================================
-- SCANNER CORE (melhorado)
-- ================================================================
local _SC = {}; _SC.__index = _SC

function _SC.new(logger, riskEngine, obfDetector, filters)
    local self = setmetatable({}, _SC)
    self.logger = logger
    self.risk = riskEngine
    self.obf = obfDetector
    self.filters = filters -- referência para filtros adicionais
    self.results = {
        remote_events = {}, remote_functions = {}, bindable_events = {},
        scripts = {}, suspicious = {}, vulnerabilities = {},
    }
    self.count = 0
    self.scanning = false
    self.connections = {}
    self.maxDepth = 50
    -- Controle de carga assíncrona
    self.asyncQueue = {}
    self.asyncLimit = 5  -- máximo simultâneo
    self.asyncRunning = 0
    return self
end

function _SC:scanInstance(inst, depth)
    depth = depth or 0
    if depth > self.maxDepth then return end
    if not inst then return end

    local name, class, path = "?", "?", "?"
    pcall(function() name = inst.Name end)
    pcall(function() class = inst.ClassName end)
    pcall(function() path = inst:GetFullName() end)
    if path == "?" then path = name end

    -- RemoteEvent
    if class == "RemoteEvent" then self:_regRemote(inst, path, "RemoteEvent") end
    if class == "RemoteFunction" then self:_regRemote(inst, path, "RemoteFunction") end
    if class == "BindableEvent" then
        self.results.bindable_events[#self.results.bindable_events+1] = {
            name=name, path=path, class=class, timestamp=os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
    end

    -- Scripts
    if class == "LocalScript" or class == "Script" or class == "ModuleScript" then
        self:_scanScript(inst, path, class)
    end

    -- Filhos
    local children = {}
    pcall(function() children = inst:GetChildren() end)
    if type(children) ~= "table" then pcall(function() children = inst.children or {} end) end
    for _, child in ipairs(children or {}) do
        self:scanInstance(child, depth + 1)
    end
end

function _SC:_regRemote(inst, path, class)
    local entry = {
        name = inst.Name, path = path, class = class,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"), parent = "",
    }
    pcall(function() entry.parent = inst.Parent and inst.Parent.Name or "nil" end)

    local tbl = class == "RemoteEvent" and self.results.remote_events or self.results.remote_functions
    tbl[#tbl + 1] = entry

    -- Verificar nome suspeito
    local suspPatterns = {".*Event.*",".*Remote.*",".*Fire.*",".*Send.*",".*Handler.*",".*Callback.*"}
    for _, p in ipairs(suspPatterns) do
        if inst.Name:match(p) then
            entry.suspicious = true
            self.results.suspicious[#self.results.suspicious+1] = {
                type = "SUSPICIOUS_"..class:upper(), details = entry,
            }
            break
        end
    end

    if self.logger then
        self.logger:debug("SCAN", class..": "..path)
    end
end

function _SC:_scanScript(inst, path, class)
    local source
    pcall(function() source = inst.Source end)
    if not source then pcall(function() if decompile then source = decompile(inst) end end) end

    local entry = {
        name = inst.Name, path = path, class = class,
        has_source = source ~= nil,
        source_length = source and #source or 0,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    }
    pcall(function() entry.enabled = inst.Enabled ~= false end)

    if source then
        -- 🔥 Risk Score (contextual!)
        if self.risk then
            local analysis = self.risk:analyze(source, path)
            entry.risk_score = analysis.score
            entry.risk_level = analysis.level
            entry.risk_findings = #analysis.findings
            entry.risk_combos = #analysis.combos

            if analysis.level == "HIGH" or analysis.level == "CRITICAL" then
                entry.suspicious = true
                self.results.suspicious[#self.results.suspicious+1] = {
                    type = "HIGH_RISK_SCRIPT",
                    script_path = path,
                    risk = analysis,
                }
            end
        end

        -- 🧠 Obfuscation detection
        if self.obf then
            local obfDets = self.obf:analyze(source, path)
            if #obfDets > 0 then
                entry.obfuscated = true
                entry.obfuscation_techniques = #obfDets
                self.results.suspicious[#self.results.suspicious+1] = {
                    type = "OBFUSCATED_SCRIPT",
                    script_path = path,
                    detections = obfDets,
                }
            end
        end
    end

    self.results.scripts[#self.results.scripts+1] = entry
end

function _SC:scanServices(gameRef)
    if not gameRef then return end
    self.scanning = true
    self.count = self.count + 1
    if self.logger then
        self.logger:info("SCAN", string.format("⚡ Scan #%d iniciado", self.count))
    end

    local svcs = {
        "ReplicatedStorage","ReplicatedFirst","ServerScriptService","ServerStorage",
        "Workspace","Players","Lighting","StarterGui","StarterPack",
        "StarterPlayer","Chat","SoundService","Teams",
    }
    for _, s in ipairs(svcs) do
        local ok, svc = pcall(function() return gameRef:GetService(s) end)
        if ok and svc then self:scanInstance(svc, 0) end
    end

    self.scanning = false
    if self.logger then
        self.logger:info("SCAN", "⚡ Scan concluído", self:getSummary())
    end
end

--- Scan seletivo
function _SC:scanSelective(gameRef, serviceList)
    if not gameRef or not serviceList then return end
    self.scanning = true
    self.count = self.count + 1
    for _, s in ipairs(serviceList) do
        local ok, svc = pcall(function() return gameRef:GetService(s) end)
        if ok and svc then self:scanInstance(svc, 0) end
    end
    self.scanning = false
end

--- Scan assíncrono com controle de carga
function _SC:scanAsync(gameRef, callback)
    local hasTask = pcall(function() return task and task.defer end)
    if not hasTask then
        self:scanServices(gameRef)
        if callback then callback(self:getSummary()) end
        return
    end
    task.defer(function()
        self:scanServices(gameRef)
        if callback then callback(self:getSummary()) end
    end)
end

function _SC:monitorRemote(remote, callback)
    if not remote then return nil end
    local conn
    pcall(function()
        if remote.OnClientEvent then
            conn = remote.OnClientEvent:Connect(function(...)
                local args = { ... }
                local entry = {
                    remote_name = remote.Name, arg_count = #args,
                    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                }
                pcall(function() entry.remote_path = remote:GetFullName() end)
                if callback then callback(entry) end
                if self.logger then
                    self.logger:info("MONITOR", string.format(
                        "📡 %s fired (%d args)", remote.Name, #args
                    ), entry)
                end
            end)
            if conn then self.connections[#self.connections+1] = conn end
        end
    end)
    return conn
end

function _SC:disconnectAll()
    for _, c in ipairs(self.connections) do
        pcall(function() c:Disconnect() end)
    end
    self.connections = {}
end

function _SC:getSummary()
    return {
        scan_count = self.count,
        remote_events = #self.results.remote_events,
        remote_functions = #self.results.remote_functions,
        bindable_events = #self.results.bindable_events,
        scripts_analyzed = #self.results.scripts,
        suspicious_items = #self.results.suspicious,
    }
end

function _SC:getResults() return self.results end

function _SC:exportJSON()
    return _J.pretty({
        version = "2.0.0", scan_count = self.count,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        summary = self:getSummary(), results = self.results,
    })
end

function _SC:save(fp)
    local json = self:exportJSON()
    local ok = false
    pcall(function() if writefile then writefile(fp, json); ok=true end end)
    if not ok then pcall(function()
        local f = io.open(fp, "w"); if f then f:write(json); f:close(); ok=true end
    end) end
    return ok
end

function _SC:reset()
    self.results = {
        remote_events={}, remote_functions={}, bindable_events={},
        scripts={}, suspicious={}, vulnerabilities={},
    }
    self.count = 0; self.connections = {}
end

-- ================================================================
-- VULNERABILITY DETECTOR (integrado com Risk Score)
-- ================================================================
local _VD = {}; _VD.__index = _VD

local VULN_DB = {
    {id="VULN-CI-001",name="Uso de loadstring",cat="CODE_INJECTION",sev="CRITICAL",
     ind={"loadstring"},fix="Evitar loadstring. Usar módulos pré-compilados."},
    {id="VULN-CI-002",name="Require dinâmico",cat="CODE_INJECTION",sev="HIGH",
     ind={"require"},fix="Usar apenas IDs de módulo estáticos."},
    {id="VULN-DE-001",name="HTTP para domínio externo",cat="DATA_EXFILTRATION",sev="HIGH",
     ind={"HttpGet","HttpPost","syn.request","http_request"},fix="Whitelist de domínios."},
    {id="VULN-MM-001",name="Manipulação de metatables",cat="MEMORY_MANIPULATION",sev="CRITICAL",
     ind={"getrawmetatable","setrawmetatable"},fix="Proteger metatables com __metatable."},
    {id="VULN-MM-002",name="Hook de funções",cat="MEMORY_MANIPULATION",sev="CRITICAL",
     ind={"hookfunction","hookmetamethod"},fix="Verificação de integridade de funções."},
    {id="VULN-PE-001",name="Acesso a ambiente global",cat="PRIVILEGE_ESCALATION",sev="HIGH",
     ind={"getgenv","getrenv","getfenv","setfenv"},fix="Isolar ambientes de execução."},
    {id="VULN-PE-002",name="Manipulação de upvalues",cat="PRIVILEGE_ESCALATION",sev="HIGH",
     ind={"debug.setupvalue","debug.setconstant"},fix="Evitar dados sensíveis em upvalues."},
    {id="VULN-IV-001",name="Simulação de input",cat="INPUT_VALIDATION",sev="MEDIUM",
     ind={"fireclickdetector","firetouchinterest","fireproximityprompt","firesignal"},fix="Validação server-side."},
    {id="VULN-AB-001",name="Bypass de namecall",cat="AUTH_BYPASS",sev="HIGH",
     ind={"getnamecallmethod","setnamecallmethod"},fix="Verificações server-side independentes."},
    {id="VULN-RE-001",name="RemoteEvent sem validação",cat="REMOTE_ABUSE",sev="MEDIUM",
     ind={"FireServer","OnServerEvent"},fix="Validação de tipo e limites."},
    {id="VULN-OB-001",name="Código ofuscado detectado",cat="OBFUSCATION",sev="HIGH",
     ind={"_OBFUSCATION_"},fix="Investigar script ofuscado. Possível payload malicioso."},
}

function _VD.new(logger)
    local self = setmetatable({}, _VD)
    self.logger = logger
    self.vulns = {}
    self.stats = { total=0, by_severity={LOW=0,MEDIUM=0,HIGH=0,CRITICAL=0}, by_category={} }
    return self
end

function _VD:_isDup(v)
    for _, e in ipairs(self.vulns) do
        if e.vuln_id == v.vuln_id and e.source == v.source and e.line == v.line then return true end
    end
    return false
end

--- Analisa resultados do Risk Score para gerar vulnerabilidades
function _VD:analyzeRiskResults(riskAnalyses)
    for _, analysis in ipairs(riskAnalyses) do
        if analysis.level ~= "NONE" and analysis.level ~= "LOW" then
            for _, finding in ipairs(analysis.findings or {}) do
                for _, vdef in ipairs(VULN_DB) do
                    for _, ind in ipairs(vdef.ind) do
                        if finding.pattern == ind or finding.pattern:find(ind, 1, true) then
                            local v = {
                                vuln_id = vdef.id, name = vdef.name,
                                category = vdef.cat, severity = vdef.sev,
                                remediation = vdef.fix,
                                source = analysis.source,
                                risk_score = analysis.score,
                                risk_level = analysis.level,
                                line = finding.line,
                                timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                            }
                            if not self:_isDup(v) then
                                self.vulns[#self.vulns+1] = v
                                self.stats.total = self.stats.total + 1
                                self.stats.by_severity[vdef.sev] = (self.stats.by_severity[vdef.sev] or 0) + 1
                                self.stats.by_category[vdef.cat] = (self.stats.by_category[vdef.cat] or 0) + 1
                                if self.logger then
                                    self.logger:warn("VULN", string.format(
                                        "🛡️ [%s] %s em %s [%s] score:%.1f",
                                        v.vuln_id, v.name, v.source, v.severity, analysis.score
                                    ))
                                end
                            end
                            break
                        end
                    end
                end
            end
            -- Combos geram vulnerabilidades extras
            for _, combo in ipairs(analysis.combos or {}) do
                local v = {
                    vuln_id = "VULN-COMBO", name = combo.name,
                    category = "COMBO_ATTACK", severity = "CRITICAL",
                    remediation = "Investigar combinação perigosa de padrões.",
                    source = analysis.source,
                    risk_score = analysis.score,
                    risk_level = analysis.level,
                    combo_patterns = combo.patterns,
                    multiplier = combo.multiplier,
                    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                }
                if not self:_isDup(v) then
                    self.vulns[#self.vulns+1] = v
                    self.stats.total = self.stats.total + 1
                    self.stats.by_severity["CRITICAL"] = (self.stats.by_severity["CRITICAL"] or 0) + 1
                    self.stats.by_category["COMBO_ATTACK"] = (self.stats.by_category["COMBO_ATTACK"] or 0) + 1
                end
            end
        end
    end
end

--- Analisa resultados do scanner
function _VD:analyzeScanResults(scanResults)
    if not scanResults then return end
    -- Verificar remotes suspeitos
    for _, r in ipairs(scanResults.remote_events or {}) do
        if r.suspicious then
            local v = {
                vuln_id="VULN-RE-DYN", name="RemoteEvent potencialmente vulnerável",
                category="REMOTE_ABUSE", severity="MEDIUM",
                source=r.path, timestamp=os.date("!%Y-%m-%dT%H:%M:%SZ"),
                remediation="Revisar handler server-side.",
            }
            if not self:_isDup(v) then
                self.vulns[#self.vulns+1] = v
                self.stats.total = self.stats.total + 1
                self.stats.by_severity["MEDIUM"] = (self.stats.by_severity["MEDIUM"] or 0) + 1
            end
        end
    end
end

function _VD:_riskLevel()
    if self.stats.by_severity.CRITICAL > 0 then return "CRITICAL"
    elseif self.stats.by_severity.HIGH > 0 then return "HIGH"
    elseif self.stats.by_severity.MEDIUM > 0 then return "MEDIUM"
    elseif self.stats.by_severity.LOW > 0 then return "LOW"
    else return "NONE" end
end

function _VD:_recommendations()
    local recs = {}; local seen = {}
    local map = {
        CODE_INJECTION="Eliminar loadstring e require dinâmico.",
        DATA_EXFILTRATION="Whitelist de domínios para HTTP.",
        MEMORY_MANIPULATION="Proteger metatables. Verificar integridade de funções.",
        PRIVILEGE_ESCALATION="Isolar ambientes. Evitar dados sensíveis em upvalues.",
        AUTH_BYPASS="Verificações server-side independentes.",
        INPUT_VALIDATION="Validar interações no servidor. Cooldowns.",
        REMOTE_ABUSE="Validação rigorosa em RemoteEvents. Rate limiting.",
        COMBO_ATTACK="Investigar combinações perigosas. Isolar componentes.",
        OBFUSCATION="Auditar scripts ofuscados. Possíveis payloads.",
    }
    for _, v in ipairs(self.vulns) do
        if not seen[v.category] then
            seen[v.category] = true
            recs[#recs+1] = { category=v.category, priority=v.severity, recommendation=map[v.category] or "Revisar." }
        end
    end
    return recs
end

function _VD:generateReport()
    local sorted = {}
    local order = {CRITICAL=1,HIGH=2,MEDIUM=3,LOW=4}
    for _, v in ipairs(self.vulns) do sorted[#sorted+1] = v end
    table.sort(sorted, function(a,b) return (order[a.severity] or 5) < (order[b.severity] or 5) end)
    return {
        version="2.0.0", generated=os.date("!%Y-%m-%dT%H:%M:%SZ"),
        summary={total=self.stats.total, by_severity=self.stats.by_severity, by_category=self.stats.by_category, risk_level=self:_riskLevel()},
        vulnerabilities=sorted, recommendations=self:_recommendations(),
    }
end

function _VD:exportJSON() return _J.pretty(self:generateReport()) end

function _VD:save(fp)
    local json = self:exportJSON(); local ok = false
    pcall(function() if writefile then writefile(fp, json); ok=true end end)
    if not ok then pcall(function() local f=io.open(fp,"w"); if f then f:write(json); f:close(); ok=true end end) end
    return ok
end

function _VD:getVulns() return self.vulns end
function _VD:getStats() return self.stats end
function _VD:reset()
    self.vulns = {}
    self.stats = { total=0, by_severity={LOW=0,MEDIUM=0,HIGH=0,CRITICAL=0}, by_category={} }
end

-- ================================================================
-- 🎯 API PRINCIPAL: ScanningLua
-- ================================================================
local _V = "2.0.0"

print("╔══════════════════════════════════════════╗")
print("║      Scanning-Lua v".._V.."               ║")
print("║   Scanner de Segurança para Roblox      ║")
print("╚══════════════════════════════════════════╝")

-- Criar pasta de saída
pcall(function() if makefolder then makefolder("ScanningLua"); makefolder("ScanningLua/logs"); makefolder("ScanningLua/reports") end end)

-- Inicializar módulos
local logger = _L.new("INFO", false)
local antiDet = _AD.new(logger)
antiDet:enable()

local riskEngine = _RS.new(logger)
local obfDetector = _OD.new(logger)
local scanner = _SC.new(logger, riskEngine, obfDetector)
local vulnDetector = _VD.new(logger)
local networkMon = _NM.new(logger)
local envFinger = _EF.new(logger)
local discord = _DW.new(nil, logger)

-- Instância do GUI (será inicializada no Roblox)
local _guiInstance = nil

logger:info("INIT", "Todos os módulos v2 carregados")

-- API pública
local ScanningLua = { _VERSION = _V }

--- Scan completo
function ScanningLua.fullScan(gameInstance)
    local target = gameInstance
    if not target then pcall(function() target = game end) end

    logger:info("MAIN", "═══ SCAN COMPLETO INICIADO ═══")

    -- 1. Fingerprint do ambiente
    logger:info("MAIN", "[1/5] Fingerprinting ambiente...")
    local envResult = envFinger:scan()

    -- 2. Hooks de rede
    logger:info("MAIN", "[2/5] Instalando monitor de rede...")
    networkMon:installHooks()

    -- 3. Scan de serviços
    if target then
        logger:info("MAIN", "[3/5] Escaneando serviços...")
        scanner:scanServices(target)
    else
        logger:warn("MAIN", "[3/5] game não disponível - scan ignorado")
    end

    -- 4. Análise de vulnerabilidades (baseada em Risk Score)
    logger:info("MAIN", "[4/5] Analisando vulnerabilidades...")
    vulnDetector:analyzeRiskResults(riskEngine:getAnalyses())
    vulnDetector:analyzeScanResults(scanner:getResults())

    -- 5. Análise de rede
    logger:info("MAIN", "[5/5] Analisando tráfego...")
    local netAlerts = networkMon:analyzeTraffic()

    -- Calcular score total
    local totalScore = 0
    for _, a in ipairs(riskEngine:getAnalyses()) do totalScore = totalScore + a.score end

    local summary = {
        scan_results = scanner:getSummary(),
        vulnerability_stats = vulnDetector:getStats(),
        network_stats = networkMon:getStats(),
        network_alerts = #netAlerts,
        obfuscation_stats = obfDetector:getStats(),
        environment = {
            executor = envResult.executor and envResult.executor.name or "?",
            risk = envResult.risk and envResult.risk.level or "?",
        },
        total_risk_score = math.floor(totalScore * 100) / 100,
    }

    logger:info("MAIN", "═══ SCAN COMPLETO FINALIZADO ═══", summary)

    -- Salvar automaticamente
    ScanningLua.saveAll()

    -- Discord webhook
    discord:sendSummary(summary)

    return summary
end

--- Analisar código com score de risco contextual
function ScanningLua.scanCode(code, source)
    if type(code) ~= "string" then return { score=0, level="NONE" } end
    source = source or "direct_input"

    -- Risk Score
    local risk = riskEngine:analyze(code, source)

    -- Obfuscação
    local obf = obfDetector:analyze(code, source)

    -- Vulnerabilidades
    vulnDetector:analyzeRiskResults({ risk })

    return {
        source = source,
        risk = risk,
        obfuscation = obf,
        vulnerabilities = vulnDetector:getVulns(),
    }
end

--- Analisar instância de script
function ScanningLua.scanScript(inst)
    if not inst then return nil end
    local source
    pcall(function() source = inst.Source end)
    if not source then pcall(function() if decompile then source = decompile(inst) end end) end
    if source then
        local name = "unknown"
        pcall(function() name = inst:GetFullName() end)
        return ScanningLua.scanCode(source, name)
    end
    logger:warn("MAIN", "Não foi possível obter source do script")
    return nil
end

--- Monitorar todos os RemoteEvents
function ScanningLua.monitorAllRemotes(callback)
    local conns = {}
    pcall(function()
        local function find(parent)
            for _, child in ipairs(parent:GetChildren()) do
                if child:IsA("RemoteEvent") or child:IsA("RemoteFunction") then
                    local c = scanner:monitorRemote(child, callback)
                    if c then conns[#conns+1] = c end
                end
                find(child)
            end
        end
        find(game:GetService("ReplicatedStorage"))
    end)
    logger:info("MAIN", string.format("📡 Monitorando %d remotes", #conns))
    return conns
end

--- Registrar request HTTP
function ScanningLua.logHTTP(method, url, headers, body)
    return networkMon:logRequest(method, url, headers, body)
end

--- Configurar Discord webhook
function ScanningLua.setDiscordWebhook(url)
    discord:setUrl(url)
    logger:info("MAIN", "Discord webhook configurado")
end

--- Salvar todos os resultados
function ScanningLua.saveAll()
    local ts = os.date("!%Y%m%d_%H%M%S")
    logger:save(string.format("ScanningLua/logs/log_%s.json", ts))
    scanner:save(string.format("ScanningLua/reports/scan_%s.json", ts))
    vulnDetector:save(string.format("ScanningLua/reports/vulns_%s.json", ts))
    pcall(function()
        local nd = networkMon:exportJSON()
        if writefile then writefile(string.format("ScanningLua/reports/network_%s.json", ts), nd) end
    end)
    logger:info("MAIN", "📁 Resultados salvos em ScanningLua/")
end

--- Relatório de vulnerabilidades
function ScanningLua.getReport() return vulnDetector:generateReport() end
function ScanningLua.getReportJSON() return vulnDetector:exportJSON() end

--- Estatísticas
function ScanningLua.getStats()
    return {
        scanner = scanner:getSummary(),
        vulnerabilities = vulnDetector:getStats(),
        network = networkMon:getStats(),
        obfuscation = obfDetector:getStats(),
        logger = logger:getStats(),
    }
end

--- Print resumo formatado
function ScanningLua.printSummary()
    local s = ScanningLua.getStats()
    local vs = s.vulnerabilities.by_severity
    print("\n╔══════════════════════════════════════════╗")
    print("║            RESUMO DO SCAN                ║")
    print("╠══════════════════════════════════════════╣")
    print(string.format("║  Scripts analisados:    %-16d ║", s.scanner.scripts_analyzed))
    print(string.format("║  RemoteEvents:          %-16d ║", s.scanner.remote_events))
    print(string.format("║  RemoteFunctions:       %-16d ║", s.scanner.remote_functions))
    print(string.format("║  Itens suspeitos:       %-16d ║", s.scanner.suspicious_items))
    print("╠══════════════════════════════════════════╣")
    print(string.format("║  🔴 CRITICAL:           %-16d ║", vs.CRITICAL))
    print(string.format("║  🟠 HIGH:               %-16d ║", vs.HIGH))
    print(string.format("║  🟡 MEDIUM:             %-16d ║", vs.MEDIUM))
    print(string.format("║  🟢 LOW:                %-16d ║", vs.LOW))
    print("╠══════════════════════════════════════════╣")
    print(string.format("║  Network requests:      %-16d ║", s.network.total))
    print(string.format("║  Network suspicious:    %-16d ║", s.network.suspicious))
    print(string.format("║  Ofuscação detectada:   %-16d ║", s.obfuscation.detected))
    print("╚══════════════════════════════════════════╝")
end

--- Fingerprint do ambiente
function ScanningLua.getEnvironment()
    return envFinger:getResult()
end

--- Resetar
function ScanningLua.reset()
    scanner:reset(); vulnDetector:reset(); networkMon:reset(); obfDetector:reset()
    logger:info("MAIN", "Todos os módulos resetados")
end

--- Shutdown
function ScanningLua.shutdown()
    logger:info("MAIN", "Encerrando Scanning-Lua...")
    scanner:disconnectAll()
    ScanningLua.saveAll()
    pcall(function()
        if _guiInstance then _guiInstance:destroy() end
    end)
    logger:flushPrints()
    print("[Scanning-Lua] Encerrado.")
end

--- Mostra a GUI interativa (#27)
function ScanningLua.showGui()
    pcall(function()
        if not _guiInstance then
            local GuiModule = loadstring(game:HttpGet(
                "https://raw.githubusercontent.com/oxomerketwere/Scanning-Lua/main/modules/gui.lua"
            ))()
            _guiInstance = GuiModule.new({}, logger)
        end
        _guiInstance:show()
        _guiInstance:update(ScanningLua.getStats())
    end)
end

--- Esconde a GUI
function ScanningLua.hideGui()
    pcall(function()
        if _guiInstance then _guiInstance:hide() end
    end)
end

--- Toggle GUI (mostra/esconde)
function ScanningLua.toggleGui()
    pcall(function()
        if _guiInstance and _guiInstance.isVisible then
            _guiInstance:hide()
        else
            ScanningLua.showGui()
        end
    end)
end

--- Atualiza dados na GUI
function ScanningLua.refreshGui()
    pcall(function()
        if _guiInstance then _guiInstance:update(ScanningLua.getStats()) end
    end)
end

--- Destrói a GUI
function ScanningLua.destroyGui()
    pcall(function()
        if _guiInstance then _guiInstance:destroy(); _guiInstance = nil end
    end)
end

-- ================================================================
-- AUTO-EXECUÇÃO (configurável)
-- ================================================================
local autoScan = true
pcall(function()
    if getgenv and getgenv().ScanningLua_AUTO_SCAN == false then
        autoScan = false
    end
end)

if autoScan then
    -- Delay aleatório (anti-detecção)
    pcall(function()
        if task and task.wait then task.wait(math.random() * 0.3) end
    end)

    print("\n[Scanning-Lua] Executando scan completo...")
    ScanningLua.fullScan()
    ScanningLua.printSummary()

    -- Auto-abrir GUI após o scan
    pcall(function()
        if task and task.wait then task.wait(1) end
        if ScanningLua.showGui then
            ScanningLua.showGui()
        end
    end)
end

print("\n[Scanning-Lua] API pronta. Comandos:")
print("  ScanningLua.fullScan()              -- Scan completo")
print("  ScanningLua.scanCode(code, name)    -- Analisar código (risk score)")
print("  ScanningLua.scanScript(inst)        -- Analisar script")
print("  ScanningLua.monitorAllRemotes(cb)   -- Monitorar remotes")
print("  ScanningLua.setDiscordWebhook(url)  -- Configurar Discord")
print("  ScanningLua.printSummary()          -- Resumo formatado")
print("  ScanningLua.getReportJSON()         -- Relatório JSON")
print("  ScanningLua.getEnvironment()        -- Fingerprint do executor")
print("  ScanningLua.saveAll()               -- Salvar relatórios")
print("  ScanningLua.showGui()               -- Abrir GUI interativa")
print("  ScanningLua.hideGui()               -- Esconder GUI")
print("  ScanningLua.toggleGui()             -- Toggle GUI")
print("  ScanningLua.refreshGui()            -- Atualizar dados na GUI")
print("  ScanningLua.shutdown()              -- Encerrar")
print("")
print("  Desativar auto-scan:")
print("  getgenv().ScanningLua_AUTO_SCAN = false")

-- Expor globalmente
pcall(function() if getgenv then getgenv().ScanningLua = ScanningLua end end)

return ScanningLua
