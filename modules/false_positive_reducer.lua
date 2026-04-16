--[[
    Scanning-Lua - False Positive Reducer Module (#26)
    Redução de falsos positivos para manter o scanner útil

    Sem isso, o scanner vira inútil com muitos alertas falsos.

    Features:
    - Whitelist configurável de padrões/scripts
    - Score mínimo para alertar
    - Análise de contexto (não só string match)
    - Histórico de falsos positivos
    - Confiança baseada em contexto
]]

local FalsePositiveReducer = {}
FalsePositiveReducer.__index = FalsePositiveReducer

--- Cria uma nova instância do redutor de falsos positivos
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table FalsePositiveReducer instance
function FalsePositiveReducer.new(config, logger)
    local self = setmetatable({}, FalsePositiveReducer)
    self.config = config or {}
    self.logger = logger

    -- Whitelist
    self.whitelistedScripts = {}   -- { [scriptPath] = true }
    self.whitelistedPatterns = {}  -- { [pattern] = true }
    self.whitelistedDomains = {}   -- { [domain] = true }

    -- Thresholds
    self.minScoreToAlert = config.MIN_SCORE_TO_ALERT or 10
    self.minSeverityToAlert = config.MIN_SEVERITY_TO_ALERT or "MEDIUM"

    -- Contextual rules
    self.contextRules = {}

    -- Stats
    self.stats = {
        total_evaluated = 0,
        alerts_suppressed = 0,
        alerts_passed = 0,
        whitelisted_scripts = 0,
        whitelisted_patterns = 0,
    }

    -- Carregar whitelists do config
    self:_loadFromConfig()

    -- Carregar regras de contexto padrão
    self:_loadDefaultContextRules()

    return self
end

--- Carrega whitelists do config
function FalsePositiveReducer:_loadFromConfig()
    if self.config.WHITELISTED_SCRIPTS then
        for _, script in ipairs(self.config.WHITELISTED_SCRIPTS) do
            self:whitelistScript(script)
        end
    end

    if self.config.WHITELISTED_PATTERNS then
        for _, pattern in ipairs(self.config.WHITELISTED_PATTERNS) do
            self:whitelistPattern(pattern)
        end
    end

    if self.config.WHITELISTED_DOMAINS then
        for _, domain in ipairs(self.config.WHITELISTED_DOMAINS) do
            self:whitelistDomain(domain)
        end
    end
end

--- Carrega regras de contexto padrão
function FalsePositiveReducer:_loadDefaultContextRules()
    -- Regras que reduzem a suspeita quando certas condições são atendidas
    self.contextRules = {
        {
            name = "DOCUMENTED_MODULE",
            description = "Módulo bem documentado com docstrings",
            condition = function(code)
                local docCount = 0
                for _ in code:gmatch("%-%-%-") do docCount = docCount + 1 end
                return docCount > 5
            end,
            adjustment = -0.3, -- Reduz score em 30%
        },
        {
            name = "TEST_FILE",
            description = "Arquivo de teste",
            condition = function(_, source)
                return source and (
                    source:find("test") or
                    source:find("spec") or
                    source:find("_test%.lua") or
                    source:find("_spec%.lua")
                )
            end,
            adjustment = -0.5, -- Reduz score em 50%
        },
        {
            name = "LARGE_ORGANIZED_CODE",
            description = "Código grande e organizado",
            condition = function(code)
                if #code < 5000 then return false end
                local lineCount = 1
                for _ in code:gmatch("\n") do lineCount = lineCount + 1 end
                local funcCount = 0
                for _ in code:gmatch("function%s+[%w_%.]+") do funcCount = funcCount + 1 end
                return lineCount > 100 and funcCount > 5
            end,
            adjustment = -0.2, -- Reduz score em 20%
        },
        {
            name = "STANDARD_ROBLOX_PATTERN",
            description = "Padrão comum de scripting Roblox legítimo",
            condition = function(code)
                -- Se usa GetService normalmente + não tem loadstring
                return code:find("GetService") and
                    not code:find("loadstring") and
                    not code:find("hookfunction")
            end,
            adjustment = -0.4, -- Reduz score em 40%
        },
        {
            name = "MINIMAL_LOADER",
            description = "Script mínimo que apenas carrega código remoto",
            condition = function(code)
                return #code < 150 and code:find("loadstring") and code:find("HttpGet")
            end,
            adjustment = 0.5, -- AUMENTA score em 50%
        },
    }
end

--- Adiciona um script à whitelist
--- @param scriptPath string Caminho do script
function FalsePositiveReducer:whitelistScript(scriptPath)
    self.whitelistedScripts[scriptPath] = true
    self.stats.whitelisted_scripts = self.stats.whitelisted_scripts + 1
end

--- Remove um script da whitelist
--- @param scriptPath string
function FalsePositiveReducer:unwhitelistScript(scriptPath)
    self.whitelistedScripts[scriptPath] = nil
end

--- Adiciona um padrão à whitelist
--- @param pattern string Padrão a ignorar
function FalsePositiveReducer:whitelistPattern(pattern)
    self.whitelistedPatterns[pattern] = true
    self.stats.whitelisted_patterns = self.stats.whitelisted_patterns + 1
end

--- Remove um padrão da whitelist
--- @param pattern string
function FalsePositiveReducer:unwhitelistPattern(pattern)
    self.whitelistedPatterns[pattern] = nil
end

--- Adiciona um domínio à whitelist
--- @param domain string Domínio a considerar seguro
function FalsePositiveReducer:whitelistDomain(domain)
    self.whitelistedDomains[domain] = true
end

--- Avalia se um alerta deve ser emitido ou suprimido
--- @param alert table Alerta a avaliar { source, score, severity, pattern, code }
--- @return boolean shouldAlert true se o alerta deve ser emitido
--- @return table evaluation Detalhes da avaliação
function FalsePositiveReducer:evaluate(alert)
    self.stats.total_evaluated = self.stats.total_evaluated + 1

    local evaluation = {
        original_score = alert.score or 0,
        adjusted_score = alert.score or 0,
        original_severity = alert.severity or "LOW",
        reasons = {},
        suppressed = false,
    }

    -- 1. Verificar whitelist de script
    if alert.source and self.whitelistedScripts[alert.source] then
        evaluation.suppressed = true
        evaluation.reasons[#evaluation.reasons + 1] = "Script está na whitelist"
        self.stats.alerts_suppressed = self.stats.alerts_suppressed + 1
        return false, evaluation
    end

    -- 2. Verificar whitelist de padrão
    if alert.pattern and self.whitelistedPatterns[alert.pattern] then
        evaluation.suppressed = true
        evaluation.reasons[#evaluation.reasons + 1] = "Padrão está na whitelist"
        self.stats.alerts_suppressed = self.stats.alerts_suppressed + 1
        return false, evaluation
    end

    -- 3. Verificar score mínimo
    local score = alert.score or 0
    if score < self.minScoreToAlert then
        evaluation.suppressed = true
        evaluation.reasons[#evaluation.reasons + 1] = string.format(
            "Score %d abaixo do mínimo %d", score, self.minScoreToAlert
        )
        self.stats.alerts_suppressed = self.stats.alerts_suppressed + 1
        return false, evaluation
    end

    -- 4. Verificar severidade mínima
    local severityOrder = { LOW = 1, MEDIUM = 2, HIGH = 3, CRITICAL = 4 }
    local alertSev = severityOrder[alert.severity or "LOW"] or 0
    local minSev = severityOrder[self.minSeverityToAlert] or 0

    if alertSev < minSev then
        evaluation.suppressed = true
        evaluation.reasons[#evaluation.reasons + 1] = string.format(
            "Severidade %s abaixo do mínimo %s", alert.severity, self.minSeverityToAlert
        )
        self.stats.alerts_suppressed = self.stats.alerts_suppressed + 1
        return false, evaluation
    end

    -- 5. Aplicar regras de contexto
    if alert.code then
        local adjustedScore = score
        for _, rule in ipairs(self.contextRules) do
            local success, ruleResult = pcall(rule.condition, alert.code, alert.source)
            if success and ruleResult then
                local adjustment = math.floor(adjustedScore * rule.adjustment)
                adjustedScore = adjustedScore + adjustment
                evaluation.reasons[#evaluation.reasons + 1] = string.format(
                    "Regra '%s': ajuste %+d (%.0f%%)",
                    rule.name, adjustment, rule.adjustment * 100
                )
            end
        end

        evaluation.adjusted_score = math.max(0, adjustedScore)

        -- Reavaliar com score ajustado
        if evaluation.adjusted_score < self.minScoreToAlert then
            evaluation.suppressed = true
            evaluation.reasons[#evaluation.reasons + 1] = string.format(
                "Score ajustado %d abaixo do mínimo %d",
                evaluation.adjusted_score, self.minScoreToAlert
            )
            self.stats.alerts_suppressed = self.stats.alerts_suppressed + 1
            return false, evaluation
        end
    end

    -- Alerta aprovado
    self.stats.alerts_passed = self.stats.alerts_passed + 1
    evaluation.reasons[#evaluation.reasons + 1] = "Alerta aprovado - passou todos os filtros"

    if self.logger then
        self.logger:debug("FP_REDUCER", string.format(
            "Alerta aprovado: source=%s, score=%d→%d, severity=%s",
            alert.source or "unknown", evaluation.original_score,
            evaluation.adjusted_score, alert.severity or "unknown"
        ))
    end

    return true, evaluation
end

--- Filtra uma lista de alertas, removendo falsos positivos
--- @param alerts table Lista de alertas
--- @return table Lista filtrada
--- @return table Lista de suprimidos
function FalsePositiveReducer:filterAlerts(alerts)
    local passed = {}
    local suppressed = {}

    for _, alert in ipairs(alerts) do
        local shouldAlert, evaluation = self:evaluate(alert)
        if shouldAlert then
            alert.fp_evaluation = evaluation
            passed[#passed + 1] = alert
        else
            alert.fp_evaluation = evaluation
            suppressed[#suppressed + 1] = alert
        end
    end

    if self.logger and #suppressed > 0 then
        self.logger:info("FP_REDUCER", string.format(
            "Filtrado: %d alertas passaram, %d suprimidos", #passed, #suppressed
        ))
    end

    return passed, suppressed
end

--- Retorna estatísticas
--- @return table
function FalsePositiveReducer:getStats()
    local total = self.stats.alerts_suppressed + self.stats.alerts_passed
    return {
        total_evaluated = self.stats.total_evaluated,
        alerts_suppressed = self.stats.alerts_suppressed,
        alerts_passed = self.stats.alerts_passed,
        suppression_rate = total > 0 and
            math.floor((self.stats.alerts_suppressed / total) * 100) or 0,
        whitelisted_scripts = self.stats.whitelisted_scripts,
        whitelisted_patterns = self.stats.whitelisted_patterns,
    }
end

--- Limpa dados
function FalsePositiveReducer:reset()
    self.stats = {
        total_evaluated = 0,
        alerts_suppressed = 0,
        alerts_passed = 0,
        whitelisted_scripts = self.stats.whitelisted_scripts,
        whitelisted_patterns = self.stats.whitelisted_patterns,
    }
end

return FalsePositiveReducer
