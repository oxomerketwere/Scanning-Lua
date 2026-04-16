--[[
    Scanning-Lua - Heuristic Engine Module (#14 + #22)
    Motor de heurística avançada com scoring tipo machine learning

    Em vez de padrões fixos, analisa COMBINAÇÃO de fatores:
    - Tamanho do script + ofuscação + HTTP → suspeito
    - Script grande + organizado → provavelmente seguro
    - Pesos configuráveis por indicador
    - Score numérico com classificação final
]]

local HeuristicEngine = {}
HeuristicEngine.__index = HeuristicEngine

--- Pesos padrão para indicadores
local DEFAULT_WEIGHTS = {
    -- Indicadores de código
    loadstring = 8,
    HttpGet = 4,
    HttpPost = 5,
    getrawmetatable = 7,
    setrawmetatable = 7,
    hookfunction = 9,
    hookmetamethod = 9,
    newcclosure = 5,
    getnamecallmethod = 4,
    setnamecallmethod = 5,
    getgenv = 6,
    getrenv = 6,
    getfenv = 5,
    setfenv = 7,
    ["debug.setupvalue"] = 8,
    ["debug.setconstant"] = 8,
    ["debug.getupvalue"] = 4,
    ["debug.getconstant"] = 4,
    fireserver = 3,
    fireclickdetector = 4,
    firetouchinterest = 4,
    fireproximityprompt = 3,
    firesignal = 4,
    ["syn.request"] = 6,
    http_request = 5,
    ["game:HttpGet"] = 5,
    decompile = 6,
    saveinstance = 4,

    -- Indicadores de ofuscação (bônus)
    known_obfuscator = 15,
    base64_payload = 8,
    hex_encoding = 6,
    string_char_construction = 5,
    minification = 3,
    high_entropy = 4,
    string_concat_evasion = 7,
}

--- Multiplicadores para combinações perigosas
local COMBO_MULTIPLIERS = {
    {
        name = "Remote Code Execution",
        indicators = { "loadstring", "HttpGet" },
        multiplier = 2.5,
        severity = "CRITICAL",
    },
    {
        name = "Full Environment Hijack",
        indicators = { "getrawmetatable", "hookfunction" },
        multiplier = 2.0,
        severity = "CRITICAL",
    },
    {
        name = "Namecall Hijack",
        indicators = { "getnamecallmethod", "setnamecallmethod" },
        multiplier = 1.8,
        severity = "HIGH",
    },
    {
        name = "Upvalue + Env Manipulation",
        indicators = { "debug.setupvalue", "getfenv" },
        multiplier = 2.0,
        severity = "CRITICAL",
    },
    {
        name = "Data Exfiltration",
        indicators = { "HttpPost", "syn.request" },
        multiplier = 1.5,
        severity = "HIGH",
    },
    {
        name = "Obfuscated Remote Execution",
        indicators = { "loadstring", "known_obfuscator" },
        multiplier = 3.0,
        severity = "CRITICAL",
    },
    {
        name = "Hook + Intercept Chain",
        indicators = { "hookfunction", "getnamecallmethod" },
        multiplier = 1.8,
        severity = "HIGH",
    },
    {
        name = "Full Debug Control",
        indicators = { "debug.setupvalue", "debug.setconstant" },
        multiplier = 2.0,
        severity = "CRITICAL",
    },
    {
        name = "Encoded Payload Execution",
        indicators = { "loadstring", "base64_payload" },
        multiplier = 2.5,
        severity = "CRITICAL",
    },
    {
        name = "Environment Manipulation Chain",
        indicators = { "getgenv", "setfenv" },
        multiplier = 1.5,
        severity = "HIGH",
    },
}

--- Classificação por score
local SCORE_LEVELS = {
    { min = 0, max = 0, level = "NONE", color = "🟢" },
    { min = 1, max = 9, level = "LOW", color = "🟡" },
    { min = 10, max = 24, level = "MEDIUM", color = "🟠" },
    { min = 25, max = 49, level = "HIGH", color = "🔴" },
    { min = 50, max = math.huge, level = "CRITICAL", color = "⚫" },
}

--- Cria uma nova instância do motor heurístico
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table HeuristicEngine instance
function HeuristicEngine.new(config, logger)
    local self = setmetatable({}, HeuristicEngine)
    self.config = config or {}
    self.logger = logger
    self.weights = {}
    self.analyses = {}
    self.stats = {
        total_analyzed = 0,
        by_level = { NONE = 0, LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        average_score = 0,
        max_score = 0,
    }

    -- Carregar pesos (padrão + customizados)
    for k, v in pairs(DEFAULT_WEIGHTS) do
        self.weights[k] = v
    end
    if config.CUSTOM_WEIGHTS then
        for k, v in pairs(config.CUSTOM_WEIGHTS) do
            self.weights[k] = v
        end
    end

    return self
end

--- Analisa código e calcula score de risco
--- @param code string Código a analisar
--- @param source string Origem do código
--- @param obfuscationDetections table|nil Detecções de ofuscação (do ObfuscationDetector)
--- @return table Resultado da análise heurística
function HeuristicEngine:analyze(code, source, obfuscationDetections)
    if type(code) ~= "string" then
        return { score = 0, level = "NONE", indicators = {}, combos = {} }
    end

    self.stats.total_analyzed = self.stats.total_analyzed + 1
    source = source or "unknown"

    local indicators = {}
    local totalScore = 0

    -- 1. Detectar indicadores de código
    local codeIndicators = {
        { key = "loadstring", pattern = "loadstring" },
        { key = "HttpGet", pattern = "HttpGet" },
        { key = "HttpPost", pattern = "HttpPost" },
        { key = "getrawmetatable", pattern = "getrawmetatable" },
        { key = "setrawmetatable", pattern = "setrawmetatable" },
        { key = "hookfunction", pattern = "hookfunction" },
        { key = "hookmetamethod", pattern = "hookmetamethod" },
        { key = "newcclosure", pattern = "newcclosure" },
        { key = "getnamecallmethod", pattern = "getnamecallmethod" },
        { key = "setnamecallmethod", pattern = "setnamecallmethod" },
        { key = "getgenv", pattern = "getgenv" },
        { key = "getrenv", pattern = "getrenv" },
        { key = "getfenv", pattern = "getfenv" },
        { key = "setfenv", pattern = "setfenv" },
        { key = "debug.setupvalue", pattern = "debug%.setupvalue" },
        { key = "debug.setconstant", pattern = "debug%.setconstant" },
        { key = "debug.getupvalue", pattern = "debug%.getupvalue" },
        { key = "debug.getconstant", pattern = "debug%.getconstant" },
        { key = "fireserver", pattern = "[Ff]ire[Ss]erver" },
        { key = "fireclickdetector", pattern = "fireclickdetector" },
        { key = "firetouchinterest", pattern = "firetouchinterest" },
        { key = "fireproximityprompt", pattern = "fireproximityprompt" },
        { key = "firesignal", pattern = "firesignal" },
        { key = "syn.request", pattern = "syn%.request" },
        { key = "http_request", pattern = "http_request" },
        { key = "game:HttpGet", pattern = "game:HttpGet" },
        { key = "decompile", pattern = "decompile" },
        { key = "saveinstance", pattern = "saveinstance" },
    }

    for _, ind in ipairs(codeIndicators) do
        local count = 0
        for _ in code:gmatch(ind.pattern) do
            count = count + 1
        end
        if count > 0 then
            local weight = self.weights[ind.key] or 1
            local points = weight * math.min(count, 3) -- Cap de 3x por indicador
            indicators[ind.key] = {
                count = count,
                weight = weight,
                points = points,
            }
            totalScore = totalScore + points
        end
    end

    -- 2. Bônus de ofuscação
    if obfuscationDetections then
        for _, detection in ipairs(obfuscationDetections) do
            local technique = detection.technique
            local key = nil

            if technique == "KNOWN_OBFUSCATOR" then key = "known_obfuscator"
            elseif technique == "HIGH_ENTROPY_STRING" then key = "high_entropy"
            elseif technique == "HEX_STRING_ENCODING" then key = "hex_encoding"
            elseif technique == "STRING_CHAR_CONSTRUCTION" then key = "string_char_construction"
            elseif technique == "CODE_MINIFICATION" then key = "minification"
            elseif technique == "STRING_CONCATENATION_EVASION" then key = "string_concat_evasion"
            end

            if key then
                local weight = self.weights[key] or 3
                indicators[key] = {
                    count = 1,
                    weight = weight,
                    points = weight,
                    technique = technique,
                }
                totalScore = totalScore + weight
            end
        end
    end

    -- 3. Aplicar multiplicadores de combinação
    local appliedCombos = {}
    local bestMultiplier = 1.0

    for _, combo in ipairs(COMBO_MULTIPLIERS) do
        local allPresent = true
        for _, ind in ipairs(combo.indicators) do
            if not indicators[ind] then
                allPresent = false
                break
            end
        end

        if allPresent then
            appliedCombos[#appliedCombos + 1] = {
                name = combo.name,
                multiplier = combo.multiplier,
                severity = combo.severity,
                indicators = combo.indicators,
            }
            if combo.multiplier > bestMultiplier then
                bestMultiplier = combo.multiplier
            end
        end
    end

    -- Aplicar o maior multiplicador encontrado
    if bestMultiplier > 1.0 then
        totalScore = math.floor(totalScore * bestMultiplier)
    end

    -- 4. Ajustes de contexto (reduz falso positivo)
    local contextAdjust = self:_analyzeContext(code)
    totalScore = math.max(0, totalScore + contextAdjust.adjustment)

    -- 5. Determinar nível final
    local level = "NONE"
    local color = "🟢"
    for _, sl in ipairs(SCORE_LEVELS) do
        if totalScore >= sl.min and totalScore <= sl.max then
            level = sl.level
            color = sl.color
            break
        end
    end

    -- Construir resultado
    local result = {
        score = totalScore,
        level = level,
        color = color,
        source = source,
        indicators = indicators,
        combos = appliedCombos,
        context = contextAdjust,
        best_multiplier = bestMultiplier,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    }

    -- Atualizar estatísticas
    self.stats.by_level[level] = (self.stats.by_level[level] or 0) + 1
    if totalScore > self.stats.max_score then
        self.stats.max_score = totalScore
    end
    local totalAnalyzed = self.stats.total_analyzed
    self.stats.average_score = ((self.stats.average_score * (totalAnalyzed - 1)) + totalScore) / totalAnalyzed

    -- Armazenar análise
    self.analyses[#self.analyses + 1] = result

    if self.logger then
        self.logger:info("HEURISTIC", string.format(
            "%s Score: %d (%s) para %s [%d indicadores, %d combos]",
            color, totalScore, level, source,
            self:_countIndicators(indicators), #appliedCombos
        ), result)
    end

    return result
end

--- Analisa contexto do código para ajustar score
--- @param code string
--- @return table Ajuste contextual
function HeuristicEngine:_analyzeContext(code)
    local adjustment = 0
    local factors = {}

    local codeLength = #code
    local lineCount = 1
    for _ in code:gmatch("\n") do lineCount = lineCount + 1 end

    -- Script muito pequeno com indicadores → mais suspeito
    if codeLength < 200 and lineCount < 10 then
        adjustment = adjustment + 5
        factors[#factors + 1] = {
            factor = "SMALL_SCRIPT",
            adjustment = 5,
            description = "Script pequeno com indicadores - mais suspeito",
        }
    end

    -- Script grande e bem organizado → provavelmente legítimo
    if codeLength > 5000 and lineCount > 100 then
        local commentCount = 0
        for _ in code:gmatch("%-%-") do commentCount = commentCount + 1 end
        local functionCount = 0
        for _ in code:gmatch("function%s+[%w_%.]+") do functionCount = functionCount + 1 end

        if commentCount > 10 and functionCount > 5 then
            adjustment = adjustment - 10
            factors[#factors + 1] = {
                factor = "WELL_ORGANIZED",
                adjustment = -10,
                description = "Script grande, comentado e organizado - provavelmente legítimo",
            }
        end
    end

    -- Script com muitos comentários de documentação → provavelmente framework
    local docComments = 0
    for _ in code:gmatch("%-%-%-") do docComments = docComments + 1 end
    if docComments > 10 then
        adjustment = adjustment - 5
        factors[#factors + 1] = {
            factor = "DOCUMENTED_CODE",
            adjustment = -5,
            description = "Código bem documentado - reduz suspeita",
        }
    end

    -- Script com apenas require e loadstring sem outro código → altamente suspeito
    if codeLength < 100 and code:find("loadstring") and code:find("HttpGet") then
        adjustment = adjustment + 10
        factors[#factors + 1] = {
            factor = "MINIMAL_LOADER",
            adjustment = 10,
            description = "Script mínimo com loadstring+HttpGet - loader clássico",
        }
    end

    return {
        adjustment = adjustment,
        factors = factors,
        code_length = codeLength,
        line_count = lineCount,
    }
end

--- Conta indicadores encontrados
--- @param indicators table
--- @return number
function HeuristicEngine:_countIndicators(indicators)
    local count = 0
    for _ in pairs(indicators) do count = count + 1 end
    return count
end

--- Retorna todas as análises
--- @return table
function HeuristicEngine:getAnalyses()
    return self.analyses
end

--- Retorna estatísticas
--- @return table
function HeuristicEngine:getStats()
    return self.stats
end

--- Limpa análises
function HeuristicEngine:reset()
    self.analyses = {}
    self.stats = {
        total_analyzed = 0,
        by_level = { NONE = 0, LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        average_score = 0,
        max_score = 0,
    }
end

return HeuristicEngine
