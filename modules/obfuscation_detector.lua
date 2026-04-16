--[[
    Scanning-Lua - Obfuscation Detector Module
    Detecta técnicas de ofuscação de código Lua
    Identifica string encoding, concatenação maliciosa, minificação e bytecode manipulation
]]

local ObfuscationDetector = {}
ObfuscationDetector.__index = ObfuscationDetector

--- Cria uma nova instância do detector de ofuscação
--- @param logger table Instância do Logger
--- @return table ObfuscationDetector instance
function ObfuscationDetector.new(logger)
    local self = setmetatable({}, ObfuscationDetector)
    self.logger = logger
    self.detections = {}
    self.stats = {
        total_analyzed = 0,
        total_detected = 0,
        by_technique = {},
    }
    return self
end

--- Analisa código em busca de técnicas de ofuscação
--- @param code string Código a ser analisado
--- @param source string Identificador da origem
--- @return table Lista de detecções de ofuscação
function ObfuscationDetector:analyze(code, source)
    if type(code) ~= "string" then return {} end

    self.stats.total_analyzed = self.stats.total_analyzed + 1
    source = source or "unknown"
    local detections = {}

    -- 1. Detecção de concatenação de strings para evasão de padrões
    self:_detectStringConcat(code, source, detections)

    -- 2. Detecção de encoding hex/octal/unicode
    self:_detectStringEncoding(code, source, detections)

    -- 3. Detecção de código minificado
    self:_detectMinification(code, source, detections)

    -- 4. Detecção de ofuscadores conhecidos
    self:_detectKnownObfuscators(code, source, detections)

    -- 5. Detecção de table.concat para construir strings
    self:_detectTableConcat(code, source, detections)

    -- 6. Detecção de string.char para construir strings
    self:_detectStringChar(code, source, detections)

    -- 7. Detecção de técnicas anti-decompile
    self:_detectAntiDecompile(code, source, detections)

    -- 8. Detecção de entropia alta (dados binários/criptografados)
    self:_detectHighEntropy(code, source, detections)

    if #detections > 0 then
        self.stats.total_detected = self.stats.total_detected + #detections
        self.detections[#self.detections + 1] = {
            source = source,
            detections = detections,
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }

        if self.logger then
            self.logger:warn("OBFUSCATION", string.format(
                "%d técnicas de ofuscação detectadas em %s", #detections, source
            ))
        end
    end

    return detections
end

--- Detecta concatenação de strings para evasão (ex: "load" .. "string")
function ObfuscationDetector:_detectStringConcat(code, source, detections)
    -- Padrões de split de keywords conhecidas
    local splitKeywords = {
        { parts = { "load", "string" }, keyword = "loadstring" },
        { parts = { "Http", "Get" }, keyword = "HttpGet" },
        { parts = { "Http", "Post" }, keyword = "HttpPost" },
        { parts = { "get", "raw", "metatable" }, keyword = "getrawmetatable" },
        { parts = { "set", "raw", "metatable" }, keyword = "setrawmetatable" },
        { parts = { "hook", "function" }, keyword = "hookfunction" },
        { parts = { "hook", "meta", "method" }, keyword = "hookmetamethod" },
        { parts = { "get", "genv" }, keyword = "getgenv" },
        { parts = { "get", "renv" }, keyword = "getrenv" },
        { parts = { "fire", "server" }, keyword = "fireserver" },
    }

    for _, entry in ipairs(splitKeywords) do
        -- Verifica se as partes existem próximas umas das outras com ".."
        local pattern = ""
        for i, part in ipairs(entry.parts) do
            if i > 1 then
                pattern = pattern .. '["\']%s*%.%.%s*["\']'
            end
            pattern = pattern .. part
        end
        if code:find(pattern) then
            local detection = {
                technique = "STRING_CONCATENATION_EVASION",
                severity = "HIGH",
                keyword_evaded = entry.keyword,
                description = string.format(
                    "Possível evasão de detecção via concatenação de string para '%s'",
                    entry.keyword
                ),
                source = source,
            }
            detections[#detections + 1] = detection
            self.stats.by_technique["STRING_CONCAT"] = (self.stats.by_technique["STRING_CONCAT"] or 0) + 1
        end
    end

    -- Detecção genérica de muitas concatenações em uma linha
    for line in code:gmatch("[^\n]+") do
        local concatCount = 0
        for _ in line:gmatch("%.%.") do
            concatCount = concatCount + 1
        end
        if concatCount >= 5 then
            detections[#detections + 1] = {
                technique = "EXCESSIVE_CONCATENATION",
                severity = "MEDIUM",
                concat_count = concatCount,
                description = string.format(
                    "Linha com %d concatenações - possível ofuscação", concatCount
                ),
                source = source,
            }
            self.stats.by_technique["EXCESSIVE_CONCAT"] = (self.stats.by_technique["EXCESSIVE_CONCAT"] or 0) + 1
            break -- Uma detecção por arquivo é suficiente
        end
    end
end

--- Detecta encoding de strings (hex, octal, unicode escape)
function ObfuscationDetector:_detectStringEncoding(code, source, detections)
    -- Hex encoding: \x41\x42
    local hexCount = 0
    for _ in code:gmatch("\\x%x%x") do
        hexCount = hexCount + 1
    end
    if hexCount >= 10 then
        detections[#detections + 1] = {
            technique = "HEX_STRING_ENCODING",
            severity = "HIGH",
            count = hexCount,
            description = string.format(
                "%d sequências hex encoding detectadas - possível payload ofuscado", hexCount
            ),
            source = source,
        }
        self.stats.by_technique["HEX_ENCODING"] = (self.stats.by_technique["HEX_ENCODING"] or 0) + 1
    end

    -- Octal encoding: \101\102
    local octalCount = 0
    for _ in code:gmatch("\\%d%d%d") do
        octalCount = octalCount + 1
    end
    if octalCount >= 10 then
        detections[#detections + 1] = {
            technique = "OCTAL_STRING_ENCODING",
            severity = "HIGH",
            count = octalCount,
            description = string.format(
                "%d sequências octal encoding detectadas", octalCount
            ),
            source = source,
        }
        self.stats.by_technique["OCTAL_ENCODING"] = (self.stats.by_technique["OCTAL_ENCODING"] or 0) + 1
    end
end

--- Detecta código minificado (linhas muito longas, sem espaços, nomes curtos)
function ObfuscationDetector:_detectMinification(code, source, detections)
    local lines = {}
    for line in code:gmatch("[^\n]+") do
        lines[#lines + 1] = line
    end

    if #lines == 0 then return end

    -- Linhas muito longas (>500 chars) indicam minificação
    local longLineCount = 0
    for _, line in ipairs(lines) do
        if #line > 500 then
            longLineCount = longLineCount + 1
        end
    end

    -- Poucas linhas com muito código = minificado
    local totalChars = #code
    local avgLineLength = totalChars / math.max(#lines, 1)

    if longLineCount >= 3 or (avgLineLength > 200 and #lines < 20 and totalChars > 2000) then
        detections[#detections + 1] = {
            technique = "CODE_MINIFICATION",
            severity = "MEDIUM",
            long_lines = longLineCount,
            avg_line_length = math.floor(avgLineLength),
            total_lines = #lines,
            description = "Código aparenta estar minificado/compactado",
            source = source,
        }
        self.stats.by_technique["MINIFICATION"] = (self.stats.by_technique["MINIFICATION"] or 0) + 1
    end

    -- Variáveis de uma letra em excesso (a, b, c, x, y, z)
    local singleVarCount = 0
    for _ in code:gmatch("local%s+[a-z]%s*=") do
        singleVarCount = singleVarCount + 1
    end
    if singleVarCount >= 15 then
        detections[#detections + 1] = {
            technique = "MINIFIED_VARIABLE_NAMES",
            severity = "LOW",
            count = singleVarCount,
            description = string.format(
                "%d variáveis de uma letra - possível código minificado/ofuscado", singleVarCount
            ),
            source = source,
        }
        self.stats.by_technique["MINIFIED_VARS"] = (self.stats.by_technique["MINIFIED_VARS"] or 0) + 1
    end
end

--- Detecta ofuscadores Lua conhecidos
function ObfuscationDetector:_detectKnownObfuscators(code, source, detections)
    local obfuscators = {
        { pattern = "IIlIIlIIlIlI", name = "Luraph", severity = "CRITICAL" },
        { pattern = "LPH_", name = "Luraph (variante)", severity = "CRITICAL" },
        { pattern = "PSU_", name = "PSU Obfuscator", severity = "CRITICAL" },
        { pattern = "Moonsec", name = "Moonsec", severity = "CRITICAL" },
        { pattern = "IllIllIllI", name = "Generic IL Obfuscator", severity = "HIGH" },
        { pattern = "xor_key", name = "XOR Obfuscator", severity = "HIGH" },
        { pattern = "bit32%.bxor", name = "Bitwise XOR Obfuscation", severity = "MEDIUM" },
        { pattern = "string%.byte.*string%.char.*for", name = "Byte-level string manipulation", severity = "HIGH" },
        { pattern = "ILIIILIIIL", name = "IronBrew Obfuscator", severity = "CRITICAL" },
        { pattern = "Bytecode", name = "Bytecode Obfuscator", severity = "HIGH" },
    }

    for _, obf in ipairs(obfuscators) do
        if code:find(obf.pattern) then
            detections[#detections + 1] = {
                technique = "KNOWN_OBFUSCATOR",
                severity = obf.severity,
                obfuscator = obf.name,
                pattern = obf.pattern,
                description = string.format(
                    "Ofuscador conhecido detectado: %s", obf.name
                ),
                source = source,
            }
            self.stats.by_technique["KNOWN_OBFUSCATOR"] = (self.stats.by_technique["KNOWN_OBFUSCATOR"] or 0) + 1
        end
    end
end

--- Detecta uso de table.concat para construir strings de código
function ObfuscationDetector:_detectTableConcat(code, source, detections)
    -- table.concat com muitos elementos = possível construção de payload
    local tconcatCount = 0
    for _ in code:gmatch("table%.concat") do
        tconcatCount = tconcatCount + 1
    end

    if tconcatCount >= 3 then
        detections[#detections + 1] = {
            technique = "TABLE_CONCAT_CONSTRUCTION",
            severity = "MEDIUM",
            count = tconcatCount,
            description = string.format(
                "%d usos de table.concat - possível construção dinâmica de código", tconcatCount
            ),
            source = source,
        }
        self.stats.by_technique["TABLE_CONCAT"] = (self.stats.by_technique["TABLE_CONCAT"] or 0) + 1
    end
end

--- Detecta uso de string.char para construir payloads
function ObfuscationDetector:_detectStringChar(code, source, detections)
    local scharCount = 0
    for _ in code:gmatch("string%.char") do
        scharCount = scharCount + 1
    end

    if scharCount >= 5 then
        detections[#detections + 1] = {
            technique = "STRING_CHAR_CONSTRUCTION",
            severity = "HIGH",
            count = scharCount,
            description = string.format(
                "%d usos de string.char - possível construção de payload caractere por caractere", scharCount
            ),
            source = source,
        }
        self.stats.by_technique["STRING_CHAR"] = (self.stats.by_technique["STRING_CHAR"] or 0) + 1
    end
end

--- Detecta técnicas anti-decompile
function ObfuscationDetector:_detectAntiDecompile(code, source, detections)
    local antiPatterns = {
        { pattern = "pcall.*error.*while%s+true", name = "Infinite loop anti-decompile" },
        { pattern = "coroutine%.wrap.*coroutine%.yield", name = "Coroutine confusion" },
        { pattern = "setfenv.*0", name = "Environment level 0 manipulation" },
        { pattern = "string%.dump", name = "Bytecode dumping" },
    }

    for _, ap in ipairs(antiPatterns) do
        if code:find(ap.pattern) then
            detections[#detections + 1] = {
                technique = "ANTI_DECOMPILE",
                severity = "HIGH",
                method = ap.name,
                description = string.format(
                    "Técnica anti-decompile detectada: %s", ap.name
                ),
                source = source,
            }
            self.stats.by_technique["ANTI_DECOMPILE"] = (self.stats.by_technique["ANTI_DECOMPILE"] or 0) + 1
        end
    end
end

--- Detecta strings com entropia alta (dados codificados/criptografados)
function ObfuscationDetector:_detectHighEntropy(code, source, detections)
    -- Procurar strings longas com caracteres aparentemente aleatórios
    for str in code:gmatch('"([^"]+)"') do
        if #str >= 100 then
            -- Calcular entropia simplificada (variação de caracteres)
            local charFreq = {}
            for i = 1, #str do
                local c = str:sub(i, i)
                charFreq[c] = (charFreq[c] or 0) + 1
            end
            local uniqueChars = 0
            for _ in pairs(charFreq) do uniqueChars = uniqueChars + 1 end

            local ratio = uniqueChars / #str
            -- Alta proporção de caracteres únicos + string longa = possível dados codificados
            if uniqueChars > 50 and ratio > 0.3 then
                detections[#detections + 1] = {
                    technique = "HIGH_ENTROPY_STRING",
                    severity = "MEDIUM",
                    string_length = #str,
                    unique_chars = uniqueChars,
                    description = string.format(
                        "String de alta entropia (%d chars, %d únicos) - possível dados criptografados/codificados",
                        #str, uniqueChars
                    ),
                    source = source,
                }
                self.stats.by_technique["HIGH_ENTROPY"] = (self.stats.by_technique["HIGH_ENTROPY"] or 0) + 1
                break -- Uma detecção por arquivo
            end
        end
    end
end

--- Retorna as detecções
--- @return table
function ObfuscationDetector:getDetections()
    return self.detections
end

--- Retorna estatísticas
--- @return table
function ObfuscationDetector:getStats()
    return self.stats
end

--- Limpa detecções
function ObfuscationDetector:reset()
    self.detections = {}
    self.stats = { total_analyzed = 0, total_detected = 0, by_technique = {} }
end

return ObfuscationDetector
