--[[
    Scanning-Lua - Filters Module
    Sistema de filtros para análise de código e detecção de padrões suspeitos
    Filtra e categoriza ameaças encontradas durante o scan
]]

local Filters = {}
Filters.__index = Filters

-- Níveis de severidade
local SEVERITY_LEVELS = {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
}

--- Cria uma nova instância do módulo de filtros
--- @param config table Configurações de filtros (de Config.Filters)
--- @param logger table Instância do Logger
--- @return table Filters instance
function Filters.new(config, logger)
    local self = setmetatable({}, Filters)
    self.config = config or {}
    self.logger = logger
    self.minSeverity = SEVERITY_LEVELS[config.MIN_SEVERITY] or SEVERITY_LEVELS.LOW
    self.matchHistory = {}
    self.severityCache = {} -- Cache de classificação de severidade
    self.whitelistedPatterns = {} -- Padrões ignorados pelo usuário
    self.stats = {
        total_scanned = 0,
        total_matches = 0,
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        by_category = {},
    }
    return self
end

--- Adiciona um padrão à whitelist (será ignorado nas análises)
--- @param pattern string Padrão a ignorar
function Filters:addWhitelist(pattern)
    self.whitelistedPatterns[pattern] = true
end

--- Remove um padrão da whitelist
--- @param pattern string Padrão a remover
function Filters:removeWhitelist(pattern)
    self.whitelistedPatterns[pattern] = nil
end

--- Classifica a severidade de um padrão encontrado (com cache)
--- @param pattern string O padrão que foi encontrado
--- @param context table Contexto adicional
--- @return string Nível de severidade
function Filters:classifySeverity(pattern, context)
    context = context or {}

    -- Verificar cache
    if self.severityCache[pattern] then
        return self.severityCache[pattern]
    end

    -- Padrões de alta criticidade (manipulação direta de ambiente/memória)
    local criticalPatterns = {
        "getrawmetatable", "setrawmetatable", "hookfunction", "hookmetamethod",
        "debug%.setupvalue", "debug%.setconstant", "setfenv",
    }
    for _, cp in ipairs(criticalPatterns) do
        if pattern:find(cp, 1, true) then
            self.severityCache[pattern] = "CRITICAL"
            return "CRITICAL"
        end
    end

    -- Padrões de alta severidade (execução de código remoto/dinâmico)
    local highPatterns = {
        "loadstring", "HttpGet", "HttpPost", "syn%.request",
        "http_request", "getfenv", "getrenv", "getgenv",
    }
    for _, hp in ipairs(highPatterns) do
        if pattern:find(hp, 1, true) then
            self.severityCache[pattern] = "HIGH"
            return "HIGH"
        end
    end

    -- Padrões de média severidade (uso de APIs sensíveis)
    local mediumPatterns = {
        "getnamecallmethod", "setnamecallmethod", "newcclosure",
        "firesignal", "fireserver", "fireclickdetector",
        "firetouchinterest", "fireproximityprompt",
        "debug%.getupvalue", "debug%.getinfo", "debug%.getconstant",
    }
    for _, mp in ipairs(mediumPatterns) do
        if pattern:find(mp, 1, true) then
            self.severityCache[pattern] = "MEDIUM"
            return "MEDIUM"
        end
    end

    -- Todos os outros padrões são de baixa severidade
    local result = "LOW"
    self.severityCache[pattern] = result
    return result
end

--- Remove comentários Lua do código para evitar falsos positivos
--- @param code string Código Lua
--- @return string Código sem comentários
function Filters:_stripComments(code)
    -- Remover comentários de bloco --[[ ... ]]
    code = code:gsub("%-%-%[%[.-%]%]", "")
    -- Remover comentários de linha -- ...
    code = code:gsub("%-%-[^\n]*", "")
    return code
end

--- Analisa uma string de código em busca de padrões suspeitos
--- @param code string Código a ser analisado
--- @param source string Origem do código (nome do script, caminho, etc.)
--- @return table Lista de matches encontrados
function Filters:analyzeCode(code, source)
    if type(code) ~= "string" then
        return {}
    end

    self.stats.total_scanned = self.stats.total_scanned + 1

    -- Remover comentários para evitar falsos positivos
    local cleanCode = self:_stripComments(code)

    local matches = {}
    local patterns = self.config.SUSPICIOUS_PATTERNS or {}

    for _, pattern in ipairs(patterns) do
        -- Pular padrões na whitelist
        if not self.whitelistedPatterns[pattern] then
            local startPos = 1
            while true do
                local matchStart, matchEnd = cleanCode:find(pattern, startPos)
                if not matchStart then
                    break
                end

                local matchedText = cleanCode:sub(matchStart, matchEnd)
                local severity = self:classifySeverity(pattern, { source = source })
                local severityLevel = SEVERITY_LEVELS[severity] or 0

                if severityLevel >= self.minSeverity then
                    -- Extrair contexto (linha onde o match foi encontrado)
                    local lineNum = 1
                    for _ in code:sub(1, matchStart):gmatch("\n") do
                        lineNum = lineNum + 1
                    end

                    -- Extrair a linha completa
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
    end

    -- Salvar no histórico
    if #matches > 0 then
        self.matchHistory[#self.matchHistory + 1] = {
            source = source,
            matches = matches,
            scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
    end

    return matches
end

--- Analisa o nome de um RemoteEvent/RemoteFunction para detectar padrões suspeitos
--- @param name string Nome do remote
--- @param remotePath string Caminho completo na hierarquia
--- @return table|nil Match encontrado ou nil
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
                    "Remote com nome suspeito: '%s' em %s",
                    name, remotePath
                ), match)
            end

            return match
        end
    end

    return nil
end

--- Verifica se um serviço está na lista de monitoramento
--- @param serviceName string Nome do serviço
--- @return boolean
function Filters:isMonitoredService(serviceName)
    local services = self.config.MONITORED_SERVICES or {}
    for _, svc in ipairs(services) do
        if svc == serviceName then
            return true
        end
    end
    return false
end

--- Analisa argumentos de RemoteEvent para dados suspeitos
--- @param args table Argumentos enviados
--- @param remoteName string Nome do remote
--- @return table Lista de alertas
function Filters:analyzeRemoteArgs(args, remoteName)
    local alerts = {}

    if type(args) ~= "table" then
        return alerts
    end

    for i, arg in ipairs(args) do
        local argType = type(arg)

        -- Strings muito longas podem indicar tentativa de overflow
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

        -- Strings que contêm código Lua embutido
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

        -- Números fora de limites normais (possível exploit de integer overflow)
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

        -- Tabelas profundamente aninhadas (DoS por recursão)
        if argType == "table" then
            local depth = Filters._getTableDepth(arg, 0, 20)
            if depth >= 20 then
                alerts[#alerts + 1] = {
                    type = "DEEP_NESTING",
                    remote = remoteName,
                    arg_index = i,
                    depth = depth,
                    severity = "MEDIUM",
                    description = "Tabela com aninhamento excessivo (possível DoS por recursão)",
                }
            end
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

--- Calcula a profundidade de uma tabela (com detecção de referência circular)
--- @param tbl table Tabela a analisar
--- @param current number Profundidade atual
--- @param maxDepth number Profundidade máxima antes de parar
--- @param seen table|nil Tabelas já visitadas (detecção de ciclo)
--- @return number Profundidade
function Filters._getTableDepth(tbl, current, maxDepth, seen)
    if current >= maxDepth then
        return current
    end
    seen = seen or {}
    if seen[tbl] then
        return current -- Referência circular detectada
    end
    seen[tbl] = true
    local maxFound = current
    for _, v in pairs(tbl) do
        if type(v) == "table" then
            local depth = Filters._getTableDepth(v, current + 1, maxDepth, seen)
            if depth > maxFound then
                maxFound = depth
            end
        end
    end
    return maxFound
end

--- Retorna estatísticas dos filtros
--- @return table
function Filters:getStats()
    return self.stats
end

--- Retorna o histórico de matches
--- @return table
function Filters:getHistory()
    return self.matchHistory
end

--- Limpa o histórico e estatísticas
function Filters:reset()
    self.matchHistory = {}
    self.stats = {
        total_scanned = 0,
        total_matches = 0,
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
        by_category = {},
    }
end

return Filters
