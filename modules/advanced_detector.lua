--[[
    Scanning-Lua - Advanced Detector Module (Nível Absurdo)
    Módulo completo de detecção avançada + heurística + ofuscação + risco

    Capacidades:
    - Detecta vulnerabilidades avançadas com linha exata
    - Analisa obfuscação com scoring
    - Calcula score inteligente combinado
    - Identifica payload remoto e extrai URLs
    - Detecta nomes suspeitos de scripts
    - Analisa URLs perigosas
    - Detecta anti-debug/anti-scan
    - Detecta padrões combinados perigosos
    - Retorna trechos críticos + ataque possível
    - Pronto para integração em JSON
]]

local AdvancedDetector = {}
AdvancedDetector.__index = AdvancedDetector

-- =========================
-- ⚙️ PADRÕES DE DETECÇÃO
-- =========================

local DETECTION_PATTERNS = {
    -- Execução remota avançada
    { pattern = "loadstring", category = "CODE_INJECTION", severity = "CRITICAL", score = 5, attack = "Execução arbitrária de código" },
    { pattern = "getfenv", category = "SANDBOX_BYPASS", severity = "HIGH", score = 4, attack = "Bypass de sandbox via manipulação de ambiente" },
    { pattern = "setfenv", category = "SANDBOX_BYPASS", severity = "CRITICAL", score = 5, attack = "Bypass de sandbox - reescrita de ambiente" },

    -- Exfiltração de dados
    { pattern = "HttpPost", category = "DATA_EXFILTRATION", severity = "HIGH", score = 4, attack = "Envio de dados do player para servidor externo" },
    { pattern = "RequestAsync", category = "DATA_EXFILTRATION", severity = "HIGH", score = 4, attack = "Exfiltração assíncrona de dados" },
    { pattern = "HttpGet", category = "NETWORK", severity = "HIGH", score = 3, attack = "Download de payload remoto" },
    { pattern = "syn%.request", category = "DATA_EXFILTRATION", severity = "HIGH", score = 4, attack = "Requisição HTTP via executor" },
    { pattern = "http_request", category = "DATA_EXFILTRATION", severity = "HIGH", score = 4, attack = "Requisição HTTP direta" },

    -- Manipulação de ambiente
    { pattern = "getgenv", category = "ENV_MANIPULATION", severity = "HIGH", score = 3, attack = "Acesso ao ambiente global do executor" },
    { pattern = "getrenv", category = "ENV_MANIPULATION", severity = "HIGH", score = 3, attack = "Acesso ao ambiente Roblox" },
    { pattern = "getrawmetatable", category = "ENV_MANIPULATION", severity = "CRITICAL", score = 4, attack = "Acesso a metatable protegida" },
    { pattern = "setreadonly", category = "ENV_MANIPULATION", severity = "CRITICAL", score = 4, attack = "Desbloquear metatables protegidas" },
    { pattern = "setrawmetatable", category = "ENV_MANIPULATION", severity = "CRITICAL", score = 4, attack = "Reescrita de metatable" },

    -- Hooking
    { pattern = "hookfunction", category = "HOOKING", severity = "CRITICAL", score = 5, attack = "Interceptação e substituição de funções" },
    { pattern = "hookmetamethod", category = "HOOKING", severity = "CRITICAL", score = 5, attack = "Interceptação de metamétodos" },
    { pattern = "newcclosure", category = "HOOKING", severity = "HIGH", score = 3, attack = "Ocultação de hook via C closure wrapper" },
    { pattern = "replaceclosure", category = "HOOKING", severity = "CRITICAL", score = 5, attack = "Substituição direta de closure" },

    -- Remote abuse
    { pattern = ":FireServer", category = "REMOTE_ABUSE", severity = "MEDIUM", score = 2, attack = "Possível abuso de RemoteEvent" },
    { pattern = ":InvokeServer", category = "REMOTE_ABUSE", severity = "MEDIUM", score = 2, attack = "Possível abuso de RemoteFunction" },
    { pattern = "fireserver", category = "REMOTE_ABUSE", severity = "MEDIUM", score = 2, attack = "Chamada FireServer (case insensitive)" },

    -- Debug manipulation
    { pattern = "debug%.getinfo", category = "ANTI_DEBUG", severity = "MEDIUM", score = 2, attack = "Inspeção de call stack (anti-scan)" },
    { pattern = "debug%.setupvalue", category = "DEBUG_MANIPULATION", severity = "CRITICAL", score = 5, attack = "Modificação de upvalue de função" },
    { pattern = "debug%.setconstant", category = "DEBUG_MANIPULATION", severity = "CRITICAL", score = 5, attack = "Modificação de constante de função" },
    { pattern = "debug%.getupvalue", category = "DEBUG_MANIPULATION", severity = "HIGH", score = 3, attack = "Leitura de upvalue de função" },
    { pattern = "debug%.getconstant", category = "DEBUG_MANIPULATION", severity = "HIGH", score = 3, attack = "Leitura de constante de função" },
    { pattern = "debug%.sethook", category = "ANTI_DEBUG", severity = "HIGH", score = 3, attack = "Hook de debug - pode interceptar scanner" },

    -- Namecall manipulation
    { pattern = "getnamecallmethod", category = "NAMECALL_HIJACK", severity = "HIGH", score = 3, attack = "Leitura do método namecall" },
    { pattern = "setnamecallmethod", category = "NAMECALL_HIJACK", severity = "HIGH", score = 4, attack = "Substituição do método namecall" },

    -- Input simulation
    { pattern = "fireclickdetector", category = "INPUT_SIMULATION", severity = "MEDIUM", score = 2, attack = "Simulação de click" },
    { pattern = "firetouchinterest", category = "INPUT_SIMULATION", severity = "MEDIUM", score = 2, attack = "Simulação de toque" },
    { pattern = "fireproximityprompt", category = "INPUT_SIMULATION", severity = "MEDIUM", score = 2, attack = "Simulação de proximity prompt" },
    { pattern = "firesignal", category = "INPUT_SIMULATION", severity = "MEDIUM", score = 2, attack = "Simulação de sinal" },

    -- Other
    { pattern = "decompile", category = "CODE_THEFT", severity = "HIGH", score = 3, attack = "Decompilação de scripts" },
    { pattern = "saveinstance", category = "CODE_THEFT", severity = "HIGH", score = 3, attack = "Salvar instância do jogo" },
    { pattern = "string%.dump", category = "ANTI_DECOMPILE", severity = "HIGH", score = 3, attack = "Dump de bytecode" },
}

-- Padrões combinados perigosos (combos)
local DANGEROUS_COMBOS = {
    {
        name = "Remote Code Execution",
        patterns = { "loadstring", "HttpGet" },
        severity = "CRITICAL",
        bonus = 8,
        attack = "Baixa e executa código externo arbitrário",
    },
    {
        name = "Encoded Remote Payload",
        patterns = { "HttpGet", "base64" },
        severity = "CRITICAL",
        bonus = 6,
        attack = "Payload remoto codificado em base64",
    },
    {
        name = "Advanced Exploit Chain",
        patterns = { "hookfunction", "getrawmetatable" },
        severity = "CRITICAL",
        bonus = 8,
        attack = "Controle total do ambiente via hook + metatable",
    },
    {
        name = "Backdoor via Require",
        patterns = { "require", "%d%d%d%d%d" },
        severity = "CRITICAL",
        bonus = 7,
        attack = "Carregamento de módulo backdoor por asset ID",
    },
    {
        name = "Data Exfiltration Chain",
        patterns = { "HttpPost", "Players" },
        severity = "HIGH",
        bonus = 5,
        attack = "Coleta e envio de dados de jogadores",
    },
    {
        name = "Full Environment Hijack",
        patterns = { "getgenv", "hookfunction" },
        severity = "CRITICAL",
        bonus = 8,
        attack = "Hook global com persistência via ambiente",
    },
    {
        name = "Sandbox Escape",
        patterns = { "getfenv", "setfenv" },
        severity = "CRITICAL",
        bonus = 7,
        attack = "Escape de sandbox via manipulação de ambientes",
    },
    {
        name = "Metatable + Readonly Bypass",
        patterns = { "getrawmetatable", "setreadonly" },
        severity = "CRITICAL",
        bonus = 8,
        attack = "Desbloquear e modificar metatables protegidas",
    },
    {
        name = "Namecall Hijack Chain",
        patterns = { "getnamecallmethod", "setnamecallmethod" },
        severity = "HIGH",
        bonus = 5,
        attack = "Interceptação e redireccionamento de métodos",
    },
    {
        name = "Debug Manipulation Chain",
        patterns = { "debug%.getupvalue", "debug%.setupvalue" },
        severity = "CRITICAL",
        bonus = 7,
        attack = "Leitura e modificação de upvalues de funções críticas",
    },
    {
        name = "Hook + Closure Hiding",
        patterns = { "hookfunction", "newcclosure" },
        severity = "CRITICAL",
        bonus = 6,
        attack = "Hook oculto via C closure wrapper",
    },
    {
        name = "Remote Spy Pattern",
        patterns = { "getnamecallmethod", "FireServer" },
        severity = "HIGH",
        bonus = 5,
        attack = "Interceptação e monitoramento de RemoteEvents",
    },
}

-- Nomes suspeitos de scripts
local SUSPICIOUS_NAMES = {
    "money", "cash", "reward", "admin", "kill", "damage",
    "godmode", "speed", "teleport", "aimbot", "esp",
    "noclip", "fly", "infinite", "hack", "cheat",
    "exploit", "inject", "executor", "backdoor",
    "autofarm", "dupe", "spawn", "bypass", "steal",
}

-- URLs/domínios suspeitos
local SUSPICIOUS_URLS = {
    { pattern = "pastebin", score = 3, reason = "Hosting de payloads (pastebin)" },
    { pattern = "discord", score = 3, reason = "Webhook/CDN Discord (possível exfiltração)" },
    { pattern = "raw%.githubusercontent", score = 3, reason = "Raw GitHub (script hosting)" },
    { pattern = "hastebin", score = 3, reason = "Hosting de payloads (hastebin)" },
    { pattern = "webhook%.site", score = 4, reason = "Serviço de exfiltração (webhook.site)" },
    { pattern = "ngrok%.io", score = 4, reason = "Tunnel C2 (ngrok)" },
    { pattern = "iplogger", score = 5, reason = "IP grabber (iplogger)" },
    { pattern = "grabify", score = 5, reason = "IP grabber (grabify)" },
    { pattern = "requestbin", score = 4, reason = "Serviço de exfiltração (requestbin)" },
    { pattern = "glitch%.me", score = 3, reason = "Hosting dinâmico (glitch)" },
    { pattern = "repl%.co", score = 3, reason = "Hosting dinâmico (replit)" },
    { pattern = "herokuapp%.com", score = 3, reason = "Hosting dinâmico (heroku)" },
}

-- Anti-debug/anti-scan patterns
local ANTI_DEBUG_PATTERNS = {
    { pattern = "debug%.getinfo", score = 2, name = "debug.getinfo", description = "Inspeção de call stack" },
    { pattern = "debug%.traceback", score = 1, name = "debug.traceback", description = "Traceback de debug" },
    { pattern = "debug%.sethook", score = 3, name = "debug.sethook", description = "Hook de debug" },
    { pattern = "string%.dump", score = 2, name = "string.dump", description = "Dump de bytecode" },
    { pattern = "pcall.*error.*while%s+true", score = 3, name = "Anti-decompile loop", description = "Loop infinito em pcall" },
    { pattern = "coroutine%.wrap.*coroutine%.yield", score = 2, name = "Coroutine confusion", description = "Confusão de coroutine" },
    { pattern = "collectgarbage", score = 1, name = "GC manipulation", description = "Manipulação do garbage collector" },
}

-- =========================
-- CONSTRUCTOR
-- =========================

--- Cria uma nova instância do Advanced Detector
--- @param logger table|nil Instância do Logger
--- @return table AdvancedDetector instance
function AdvancedDetector.new(logger)
    local self = setmetatable({}, AdvancedDetector)
    self.logger = logger
    self.scanHistory = {}
    self.stats = {
        total_scanned = 0,
        total_findings = 0,
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        by_category = {},
        combos_detected = 0,
        urls_detected = 0,
        anti_debug_detected = 0,
        max_score = 0,
        average_score = 0,
    }
    return self
end

-- =========================
-- 🧠 ANÁLISE DE OFUSCAÇÃO
-- =========================

--- Analisa nível de ofuscação do código
--- @param source string Código fonte
--- @return table Resultado da análise de ofuscação { score, details }
function AdvancedDetector:analyzeObfuscation(source)
    if type(source) ~= "string" then return { score = 0, details = {} } end

    local score = 0
    local details = {}

    -- Concatenação excessiva
    local concatCount = 0
    for _ in source:gmatch("%.%.") do
        concatCount = concatCount + 1
    end
    if concatCount > 10 then
        score = score + 2
        details[#details + 1] = {
            technique = "EXCESSIVE_CONCATENATION",
            count = concatCount,
            points = 2,
            description = string.format("%d concatenações detectadas", concatCount),
        }
    end

    -- Strings longas (possível payload codificado)
    local longStringCount = 0
    local hasEncoded = false
    for str in source:gmatch('"(.-)"') do
        if #str > 100 then
            longStringCount = longStringCount + 1
        end
        -- Base64-like
        if str:match("^[A-Za-z0-9+/=]+$") and #str > 50 then
            hasEncoded = true
        end
    end

    if longStringCount > 0 then
        score = score + math.min(longStringCount * 2, 6)
        details[#details + 1] = {
            technique = "LONG_STRINGS",
            count = longStringCount,
            points = math.min(longStringCount * 2, 6),
            description = string.format("%d strings longas (>100 chars)", longStringCount),
        }
    end

    if hasEncoded then
        score = score + 3
        details[#details + 1] = {
            technique = "BASE64_ENCODED",
            points = 3,
            description = "Strings com padrão base64 detectadas",
        }
    end

    -- Minificação (poucas linhas + muito código)
    local lineCount = 0
    for _ in source:gmatch("\n") do
        lineCount = lineCount + 1
    end
    if lineCount < 5 and #source > 300 then
        score = score + 3
        details[#details + 1] = {
            technique = "MINIFIED",
            lines = lineCount,
            code_length = #source,
            points = 3,
            description = string.format("Código minificado (%d linhas, %d chars)", lineCount, #source),
        }
    end

    -- Variáveis de uma letra (I/l obfuscation)
    local singleVarCount = 0
    for _ in source:gmatch("local%s+[a-zA-Z]%s*=") do
        singleVarCount = singleVarCount + 1
    end
    if singleVarCount >= 10 then
        score = score + 2
        details[#details + 1] = {
            technique = "SINGLE_CHAR_VARS",
            count = singleVarCount,
            points = 2,
            description = string.format("%d variáveis de 1 char", singleVarCount),
        }
    end

    -- string.char construction
    local scharCount = 0
    for _ in source:gmatch("string%.char") do
        scharCount = scharCount + 1
    end
    if scharCount >= 3 then
        score = score + 3
        details[#details + 1] = {
            technique = "STRING_CHAR",
            count = scharCount,
            points = 3,
            description = string.format("%d usos de string.char", scharCount),
        }
    end

    -- Hex encoding
    local hexCount = 0
    for _ in source:gmatch("\\x%x%x") do
        hexCount = hexCount + 1
    end
    if hexCount >= 5 then
        score = score + 2
        details[#details + 1] = {
            technique = "HEX_ENCODING",
            count = hexCount,
            points = 2,
            description = string.format("%d hex escapes", hexCount),
        }
    end

    return {
        score = score,
        is_obfuscated = score >= 3,
        details = details,
    }
end

-- =========================
-- 🔍 HELPERS
-- =========================

--- Separa código em linhas
--- @param source string
--- @return table Lista de linhas
local function getLines(source)
    local lines = {}
    for line in source:gmatch("[^\r\n]+") do
        lines[#lines + 1] = line
    end
    if #lines == 0 then
        lines[1] = source
    end
    return lines
end

--- Extrai URLs do código
--- @param source string
--- @return table Lista de URLs encontradas
local function extractUrls(source)
    local urls = {}
    local seen = {}
    for url in source:gmatch('"(https?://[^"]+)"') do
        if not seen[url] then
            urls[#urls + 1] = url
            seen[url] = true
        end
    end
    for url in source:gmatch("'(https?://[^']+)'") do
        if not seen[url] then
            urls[#urls + 1] = url
            seen[url] = true
        end
    end
    return urls
end

-- =========================
-- 💣 SCAN PRINCIPAL
-- =========================

--- Executa scan completo de um código fonte
--- @param source string Código fonte a analisar
--- @param scriptName string Nome/caminho do script
--- @return table Resultado completo { findings, score, risk, obfuscation, urls, combos, anti_debug }
function AdvancedDetector:scan(source, scriptName)
    if type(source) ~= "string" then
        return {
            findings = {},
            score = 0,
            risk = "NONE",
            obfuscation = { score = 0, is_obfuscated = false, details = {} },
            urls = {},
            combos = {},
            anti_debug = {},
            script = scriptName or "unknown",
        }
    end

    scriptName = scriptName or "unknown"
    self.stats.total_scanned = self.stats.total_scanned + 1

    local findings = {}
    local score = 0
    local lines = getLines(source)

    -- =========================
    -- 1. DETECÇÃO POR LINHA
    -- =========================
    for i, line in ipairs(lines) do
        for _, det in ipairs(DETECTION_PATTERNS) do
            if line:find(det.pattern) then
                findings[#findings + 1] = {
                    line = i,
                    snippet = line:gsub("^%s+", ""):gsub("%s+$", ""),
                    risk = det.severity,
                    reason = det.category,
                    attack = det.attack,
                    pattern = det.pattern,
                    script = scriptName,
                }
                score = score + det.score
                self.stats.total_findings = self.stats.total_findings + 1
                self.stats.by_severity[det.severity] = (self.stats.by_severity[det.severity] or 0) + 1
                self.stats.by_category[det.category] = (self.stats.by_category[det.category] or 0) + 1
            end
        end
    end

    -- =========================
    -- 2. PADRÕES COMBINADOS
    -- =========================
    local combos = {}
    for _, combo in ipairs(DANGEROUS_COMBOS) do
        local allPresent = true
        for _, pat in ipairs(combo.patterns) do
            if not source:find(pat) then
                allPresent = false
                break
            end
        end
        if allPresent then
            combos[#combos + 1] = {
                name = combo.name,
                severity = combo.severity,
                attack = combo.attack,
                patterns = combo.patterns,
                bonus = combo.bonus,
                script = scriptName,
            }
            score = score + combo.bonus
            self.stats.combos_detected = self.stats.combos_detected + 1

            if self.logger then
                self.logger:warn("ADV_DETECTOR", string.format(
                    "[COMBO] %s em %s (+%d) - %s",
                    combo.name, scriptName, combo.bonus, combo.attack
                ))
            end
        end
    end

    -- =========================
    -- 3. ANÁLISE DE OFUSCAÇÃO
    -- =========================
    local obfuscation = self:analyzeObfuscation(source)
    score = score + obfuscation.score

    -- =========================
    -- 4. NOMES SUSPEITOS
    -- =========================
    local nameScore = 0
    local matchedNames = {}
    if type(scriptName) == "string" then
        local lowerName = scriptName:lower()
        for _, name in ipairs(SUSPICIOUS_NAMES) do
            if lowerName:match(name) then
                nameScore = nameScore + 2
                matchedNames[#matchedNames + 1] = name
            end
        end
    end
    score = score + nameScore

    -- =========================
    -- 5. ANÁLISE DE URLs
    -- =========================
    local extractedUrls = extractUrls(source)
    local urlScore = 0
    local urlFindings = {}

    for _, urlPat in ipairs(SUSPICIOUS_URLS) do
        if source:find(urlPat.pattern) then
            urlScore = urlScore + urlPat.score
            urlFindings[#urlFindings + 1] = {
                pattern = urlPat.pattern,
                reason = urlPat.reason,
                score = urlPat.score,
            }
            self.stats.urls_detected = self.stats.urls_detected + 1
        end
    end
    score = score + urlScore

    -- =========================
    -- 6. ANTI-DEBUG DETECTION
    -- =========================
    local antiDebug = {}
    local antiDebugScore = 0
    for _, ad in ipairs(ANTI_DEBUG_PATTERNS) do
        if source:find(ad.pattern) then
            antiDebugScore = antiDebugScore + ad.score
            antiDebug[#antiDebug + 1] = {
                name = ad.name,
                description = ad.description,
                score = ad.score,
            }
            self.stats.anti_debug_detected = self.stats.anti_debug_detected + 1
        end
    end
    score = score + antiDebugScore

    -- =========================
    -- 7. REMOTE ABUSE FREQUENCY
    -- =========================
    local fireServerCount = 0
    for _ in source:gmatch("[Ff]ire[Ss]erver") do
        fireServerCount = fireServerCount + 1
    end
    local invokeServerCount = 0
    for _ in source:gmatch("[Ii]nvoke[Ss]erver") do
        invokeServerCount = invokeServerCount + 1
    end
    if fireServerCount >= 5 then
        score = score + 3
        findings[#findings + 1] = {
            line = 0,
            snippet = string.format("(Frequência alta: %d chamadas FireServer)", fireServerCount),
            risk = "HIGH",
            reason = "REMOTE_ABUSE_FREQUENCY",
            attack = string.format("FireServer chamado %d vezes - possível spam/exploit", fireServerCount),
            pattern = "FireServer",
            script = scriptName,
        }
    end
    if invokeServerCount >= 5 then
        score = score + 3
        findings[#findings + 1] = {
            line = 0,
            snippet = string.format("(Frequência alta: %d chamadas InvokeServer)", invokeServerCount),
            risk = "HIGH",
            reason = "REMOTE_ABUSE_FREQUENCY",
            attack = string.format("InvokeServer chamado %d vezes - possível exploit", invokeServerCount),
            pattern = "InvokeServer",
            script = scriptName,
        }
    end

    -- =========================
    -- 📊 CLASSIFICAÇÃO FINAL
    -- =========================
    local riskLevel = "NONE"
    if score >= 15 then
        riskLevel = "CRITICAL"
    elseif score >= 10 then
        riskLevel = "HIGH"
    elseif score >= 5 then
        riskLevel = "MEDIUM"
    elseif score >= 1 then
        riskLevel = "LOW"
    end

    -- Atualizar estatísticas
    if score > self.stats.max_score then
        self.stats.max_score = score
    end
    local totalScanned = self.stats.total_scanned
    self.stats.average_score = ((self.stats.average_score * (totalScanned - 1)) + score) / totalScanned

    -- Construir resultado
    local result = {
        script = scriptName,
        code_length = #source,
        -- Detecções
        findings = findings,
        finding_count = #findings,
        -- Score e risco
        score = score,
        risk = riskLevel,
        -- Sub-análises
        obfuscation = obfuscation,
        combos = combos,
        combo_count = #combos,
        urls = {
            extracted = extractedUrls,
            suspicious = urlFindings,
            score = urlScore,
        },
        anti_debug = antiDebug,
        anti_debug_score = antiDebugScore,
        -- Nomes
        suspicious_names = matchedNames,
        name_score = nameScore,
        -- Frequências
        remote_frequency = {
            fire_server = fireServerCount,
            invoke_server = invokeServerCount,
        },
        -- Timestamp
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    }

    -- Salvar no histórico
    self.scanHistory[#self.scanHistory + 1] = result

    -- Log
    if self.logger then
        self.logger:info("ADV_DETECTOR", string.format(
            "[%s] %s: score=%d (%s) | %d findings | %d combos | obf=%d | urls=%d | anti_debug=%d",
            riskLevel, scriptName, score, riskLevel,
            #findings, #combos, obfuscation.score, urlScore, antiDebugScore
        ))
    end

    return result
end

-- =========================
-- 📊 GETTERS
-- =========================

--- Retorna histórico de scans
--- @return table
function AdvancedDetector:getScanHistory()
    return self.scanHistory
end

--- Retorna estatísticas
--- @return table
function AdvancedDetector:getStats()
    return self.stats
end

--- Limpa dados
function AdvancedDetector:reset()
    self.scanHistory = {}
    self.stats = {
        total_scanned = 0,
        total_findings = 0,
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        by_category = {},
        combos_detected = 0,
        urls_detected = 0,
        anti_debug_detected = 0,
        max_score = 0,
        average_score = 0,
    }
end

return AdvancedDetector
