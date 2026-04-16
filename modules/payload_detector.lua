--[[
    Scanning-Lua - Payload Detector Module (#25)
    Detecção de payload remoto

    Detecta o padrão clássico:
        loadstring(game:HttpGet(...))()

    Melhorias:
    - Capturar URL do payload
    - Baixar conteúdo (se possível)
    - Escanear o payload baixado também
    - Rastrear cadeia de payloads
]]

local PayloadDetector = {}
PayloadDetector.__index = PayloadDetector

--- Padrões de carregamento de payload remoto
local PAYLOAD_PATTERNS = {
    {
        name = "loadstring + HttpGet",
        pattern = "loadstring%s*%((.-)HttpGet%s*%((.-)%)(.-)%)",
        severity = "CRITICAL",
        description = "Execução de código remoto via loadstring + HttpGet",
    },
    {
        name = "loadstring + HttpPost",
        pattern = "loadstring%s*%((.-)HttpPost%s*%((.-)%)(.-)%)",
        severity = "CRITICAL",
        description = "Execução de código remoto via loadstring + HttpPost",
    },
    {
        name = "loadstring + request",
        pattern = "loadstring%s*%((.-)request%s*%((.-)%)(.-)%)",
        severity = "CRITICAL",
        description = "Execução de código remoto via loadstring + request",
    },
    {
        name = "loadstring + syn.request",
        pattern = "loadstring%s*%((.-)syn%.request%s*%((.-)%)(.-)%)",
        severity = "CRITICAL",
        description = "Execução de código remoto via loadstring + syn.request",
    },
    {
        name = "Direct URL execution",
        pattern = 'game%s*:%s*HttpGet%s*%(%s*["\']https?://([^"\']+)["\']',
        severity = "HIGH",
        description = "URL de script remoto detectada via HttpGet",
    },
    {
        name = "Raw GitHub loader",
        pattern = 'raw%.githubusercontent%.com/([^"\'%s]+)',
        severity = "HIGH",
        description = "Carregamento de script de GitHub raw",
    },
    {
        name = "Pastebin loader",
        pattern = 'pastebin%.com/raw/([%w]+)',
        severity = "HIGH",
        description = "Carregamento de payload de Pastebin",
    },
    {
        name = "Discord CDN loader",
        pattern = 'cdn%.discordapp%.com/attachments/([%d/]+/[%w%.]+)',
        severity = "HIGH",
        description = "Carregamento de payload de Discord CDN",
    },
}

--- Cria uma nova instância do detector de payloads
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table PayloadDetector instance
function PayloadDetector.new(config, logger)
    local self = setmetatable({}, PayloadDetector)
    self.config = config or {}
    self.logger = logger
    self.detections = {}
    self.capturedUrls = {}
    self.downloadedPayloads = {}
    self.stats = {
        total_scanned = 0,
        payloads_detected = 0,
        urls_captured = 0,
        payloads_downloaded = 0,
        chain_depth_max = 0,
    }
    return self
end

--- Escaneia código em busca de padrões de payload remoto
--- @param code string Código a escanear
--- @param source string Origem do código
--- @return table Lista de detecções
function PayloadDetector:scan(code, source)
    if type(code) ~= "string" then return {} end

    self.stats.total_scanned = self.stats.total_scanned + 1
    source = source or "unknown"
    local detections = {}

    -- Verificar cada padrão de payload
    for _, payloadPattern in ipairs(PAYLOAD_PATTERNS) do
        if code:find(payloadPattern.pattern) then
            local detection = {
                pattern_name = payloadPattern.name,
                severity = payloadPattern.severity,
                description = payloadPattern.description,
                source = source,
                timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                urls = {},
            }

            -- Extrair URLs do código
            local urls = self:_extractUrls(code)
            detection.urls = urls

            for _, url in ipairs(urls) do
                self.capturedUrls[#self.capturedUrls + 1] = {
                    url = url,
                    source = source,
                    pattern = payloadPattern.name,
                    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                }
                self.stats.urls_captured = self.stats.urls_captured + 1
            end

            detections[#detections + 1] = detection
            self.detections[#self.detections + 1] = detection
            self.stats.payloads_detected = self.stats.payloads_detected + 1

            if self.logger then
                self.logger:warn("PAYLOAD", string.format(
                    "[%s] %s em %s - %d URLs capturadas",
                    payloadPattern.severity, payloadPattern.name,
                    source, #urls
                ), detection)
            end
        end
    end

    return detections
end

--- Extrai URLs de código
--- @param code string
--- @return table Lista de URLs encontradas
function PayloadDetector:_extractUrls(code)
    local urls = {}
    local seen = {}

    -- URLs com aspas duplas
    for url in code:gmatch('"(https?://[^"]+)"') do
        if not seen[url] then
            urls[#urls + 1] = url
            seen[url] = true
        end
    end

    -- URLs com aspas simples
    for url in code:gmatch("'(https?://[^']+)'") do
        if not seen[url] then
            urls[#urls + 1] = url
            seen[url] = true
        end
    end

    return urls
end

--- Tenta baixar e analisar um payload remoto
--- Requer ambiente com capacidade HTTP
--- @param url string URL do payload
--- @param depth number|nil Profundidade da cadeia (para evitar recursão infinita)
--- @return table|nil Resultado da análise do payload
function PayloadDetector:fetchAndAnalyze(url, depth)
    depth = depth or 0
    if depth > 3 then -- Limite de profundidade da cadeia
        if self.logger then
            self.logger:warn("PAYLOAD", "Profundidade máxima de cadeia atingida para: " .. url)
        end
        return nil
    end

    if depth > self.stats.chain_depth_max then
        self.stats.chain_depth_max = depth
    end

    local content = nil

    -- Tentar baixar o conteúdo
    pcall(function()
        if game and game.HttpGet then
            content = game:HttpGet(url)
        end
    end)

    if not content then
        pcall(function()
            if syn and syn.request then
                local resp = syn.request({ Url = url, Method = "GET" })
                content = resp and resp.Body
            end
        end)
    end

    if not content then
        pcall(function()
            if http_request then
                local resp = http_request({ Url = url, Method = "GET" })
                content = resp and resp.Body
            end
        end)
    end

    if content then
        self.stats.payloads_downloaded = self.stats.payloads_downloaded + 1

        local result = {
            url = url,
            content_length = #content,
            content_preview = content:sub(1, 500),
            depth = depth,
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }

        self.downloadedPayloads[#self.downloadedPayloads + 1] = result

        if self.logger then
            self.logger:info("PAYLOAD", string.format(
                "Payload baixado: %s (%d chars, depth %d)",
                url, #content, depth
            ))
        end

        -- Escanear o payload baixado por mais payloads (cadeia)
        local nestedDetections = self:scan(content, "payload:" .. url)
        result.nested_detections = nestedDetections

        -- Se encontrou mais URLs, podemos seguir a cadeia
        if #nestedDetections > 0 then
            result.is_chain = true
            for _, det in ipairs(nestedDetections) do
                for _, nestedUrl in ipairs(det.urls or {}) do
                    if nestedUrl ~= url then -- Evitar loop
                        local nestedResult = self:fetchAndAnalyze(nestedUrl, depth + 1)
                        if nestedResult then
                            result.chain = result.chain or {}
                            result.chain[#result.chain + 1] = nestedResult
                        end
                    end
                end
            end
        end

        return result
    end

    return nil
end

--- Classifica risco de uma URL
--- @param url string URL a classificar
--- @return table Classificação { risk_level, risk_score, reasons }
function PayloadDetector:classifyUrl(url)
    local riskScore = 0
    local reasons = {}

    -- Domínios de alto risco
    local highRiskDomains = {
        { pattern = "pastebin%.com", score = 7, reason = "Hosting de payloads" },
        { pattern = "hastebin%.com", score = 7, reason = "Hosting de payloads" },
        { pattern = "iplogger%.org", score = 9, reason = "IP grabber" },
        { pattern = "grabify%.link", score = 9, reason = "IP grabber" },
        { pattern = "ngrok%.io", score = 8, reason = "Tunnel (C2 server)" },
        { pattern = "webhook%.site", score = 7, reason = "Exfiltração de dados" },
        { pattern = "requestbin%.com", score = 7, reason = "Exfiltração de dados" },
        { pattern = "raw%.githubusercontent%.com", score = 5, reason = "Raw script hosting" },
        { pattern = "cdn%.discordapp%.com", score = 5, reason = "Discord CDN payload" },
        { pattern = "discord%.com/api/webhooks", score = 6, reason = "Discord webhook" },
    }

    -- Domínios seguros
    local safeDomains = {
        "roblox%.com",
        "rbxcdn%.com",
        "robloxcdn%.com",
    }

    -- Verificar domínios seguros
    for _, safe in ipairs(safeDomains) do
        if url:find(safe) then
            return {
                risk_level = "SAFE",
                risk_score = 0,
                reasons = { "Domínio confiável" },
            }
        end
    end

    -- Verificar domínios de risco
    for _, domain in ipairs(highRiskDomains) do
        if url:find(domain.pattern) then
            riskScore = riskScore + domain.score
            reasons[#reasons + 1] = domain.reason
        end
    end

    -- URL com extensão .lua = script
    if url:find("%.lua") then
        riskScore = riskScore + 3
        reasons[#reasons + 1] = "URL aponta para arquivo .lua"
    end

    -- Classificar
    local level = "LOW"
    if riskScore >= 8 then level = "CRITICAL"
    elseif riskScore >= 5 then level = "HIGH"
    elseif riskScore >= 3 then level = "MEDIUM" end

    return {
        risk_level = level,
        risk_score = riskScore,
        reasons = reasons,
    }
end

--- Retorna detecções
--- @return table
function PayloadDetector:getDetections()
    return self.detections
end

--- Retorna URLs capturadas
--- @return table
function PayloadDetector:getCapturedUrls()
    return self.capturedUrls
end

--- Retorna estatísticas
--- @return table
function PayloadDetector:getStats()
    return self.stats
end

--- Limpa dados
function PayloadDetector:reset()
    self.detections = {}
    self.capturedUrls = {}
    self.downloadedPayloads = {}
    self.stats = {
        total_scanned = 0,
        payloads_detected = 0,
        urls_captured = 0,
        payloads_downloaded = 0,
        chain_depth_max = 0,
    }
end

return PayloadDetector
