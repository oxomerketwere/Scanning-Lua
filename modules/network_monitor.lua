--[[
    Scanning-Lua - Network Monitor Module
    Monitora atividade de rede, requisições HTTP e comunicação
    Detecta domínios suspeitos e exfiltração de dados
]]

local JSON = require("modules.json")

local NetworkMonitor = {}
NetworkMonitor.__index = NetworkMonitor

--- Cria uma nova instância do monitor de rede
--- @param config table Configurações de rede (de Config.Network)
--- @param logger table Instância do Logger
--- @return table NetworkMonitor instance
function NetworkMonitor.new(config, logger)
    local self = setmetatable({}, NetworkMonitor)
    self.config = config or {}
    self.logger = logger
    self.requestLog = {}
    self.blockedRequests = {}
    self.hooks = {}
    self.stats = {
        total_requests = 0,
        blocked_requests = 0,
        suspicious_requests = 0,
        by_method = {},
        by_domain = {},
    }
    return self
end

--- Extrai o domínio de uma URL
--- @param url string URL completa
--- @return string|nil Domínio extraído
function NetworkMonitor.extractDomain(url)
    if type(url) ~= "string" then
        return nil
    end
    -- Remove protocolo
    local domain = url:match("^https?://([^/]+)") or url:match("^([^/]+)")
    if domain then
        -- Remove porta
        domain = domain:match("^([^:]+)")
    end
    return domain
end

--- Verifica se um domínio está na whitelist
--- @param domain string Domínio a verificar
--- @return boolean true se o domínio é permitido
function NetworkMonitor:isDomainAllowed(domain)
    if not domain then return false end

    local allowedDomains = self.config.ALLOWED_DOMAINS or {}
    domain = domain:lower()

    for _, allowed in ipairs(allowedDomains) do
        -- Verifica se o domínio termina com o domínio permitido
        if domain == allowed:lower() or domain:match("%." .. allowed:lower():gsub("%.", "%%.") .. "$") then
            return true
        end
    end

    return false
end

--- Registra uma requisição HTTP
--- @param method string Método HTTP (GET, POST, etc.)
--- @param url string URL da requisição
--- @param headers table|nil Headers da requisição
--- @param body string|nil Corpo da requisição
--- @return table Entrada de log da requisição
function NetworkMonitor:logRequest(method, url, headers, body)
    local domain = NetworkMonitor.extractDomain(url)
    local isAllowed = self:isDomainAllowed(domain)
    local isSuspicious = not isAllowed

    local entry = {
        id = #self.requestLog + 1,
        method = method or "UNKNOWN",
        url = url,
        domain = domain,
        is_allowed = isAllowed,
        is_suspicious = isSuspicious,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        has_body = body ~= nil and #(body or "") > 0,
        body_size = body and #body or 0,
        header_count = headers and #headers or 0,
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
                "Requisição suspeita: %s %s (domínio: %s)",
                method, url, domain or "unknown"
            ), entry)
        end
    elseif self.config.LOG_ALL_REQUESTS then
        if self.logger then
            self.logger:debug("NETWORK", string.format(
                "Requisição registrada: %s %s",
                method, url
            ), entry)
        end
    end

    return entry
end

--- Instala hooks para monitorar requisições HTTP (ambiente Roblox/Executor)
--- Requer funções de hooking do executor (hookfunction, etc.)
function NetworkMonitor:installHooks()
    if not self.config.MONITOR_HTTP then
        if self.logger then
            self.logger:info("NETWORK", "Monitoramento HTTP desabilitado")
        end
        return
    end

    if self.logger then
        self.logger:info("NETWORK", "Instalando hooks de monitoramento de rede")
    end

    local selfRef = self

    -- Hook para game:HttpGet (se disponível)
    local success1 = pcall(function()
        if hookfunction and game and game.HttpGet then
            local original = hookfunction(game.HttpGet, function(gameRef, url, ...)
                selfRef:logRequest("GET", url)
                return original(gameRef, url, ...)
            end)
            selfRef.hooks.httpGet = original

            if selfRef.logger then
                selfRef.logger:info("NETWORK", "Hook HttpGet instalado")
            end
        end
    end)

    -- Hook para game:HttpPost (se disponível)
    local success2 = pcall(function()
        if hookfunction and game and game.HttpPost then
            local original = hookfunction(game.HttpPost, function(gameRef, url, body, ...)
                selfRef:logRequest("POST", url, nil, body)
                return original(gameRef, url, body, ...)
            end)
            selfRef.hooks.httpPost = original

            if selfRef.logger then
                selfRef.logger:info("NETWORK", "Hook HttpPost instalado")
            end
        end
    end)

    -- Hook para syn.request / http_request / request (se disponível)
    local success3 = pcall(function()
        local requestFn = syn and syn.request or http_request or request
        if hookfunction and requestFn then
            local original = hookfunction(requestFn, function(opts, ...)
                local method = opts and opts.Method or "GET"
                local url = opts and opts.Url or "unknown"
                local body = opts and opts.Body
                selfRef:logRequest(method, url, nil, body)
                return original(opts, ...)
            end)
            selfRef.hooks.request = original

            if selfRef.logger then
                selfRef.logger:info("NETWORK", "Hook request instalado")
            end
        end
    end)

    if not success1 and not success2 and not success3 then
        if self.logger then
            self.logger:info("NETWORK", "Hooks de rede não disponíveis neste ambiente (modo offline)")
        end
    end
end

--- Analisa o tráfego registrado e gera alertas
--- @return table Lista de alertas
function NetworkMonitor:analyzeTraffic()
    local alerts = {}

    -- Verificar domínios não autorizados
    for domain, count in pairs(self.stats.by_domain) do
        if not self:isDomainAllowed(domain) then
            alerts[#alerts + 1] = {
                type = "UNAUTHORIZED_DOMAIN",
                domain = domain,
                request_count = count,
                severity = "HIGH",
                description = string.format(
                    "Domínio não autorizado '%s' detectado com %d requisições",
                    domain, count
                ),
            }
        end
    end

    -- Verificar volume anormal de requisições
    if self.stats.total_requests > 100 then
        alerts[#alerts + 1] = {
            type = "HIGH_REQUEST_VOLUME",
            total = self.stats.total_requests,
            severity = "MEDIUM",
            description = string.format(
                "Volume alto de requisições detectado: %d total",
                self.stats.total_requests
            ),
        }
    end

    -- Verificar requisições POST com corpo grande
    for _, req in ipairs(self.requestLog) do
        if req.method == "POST" and req.body_size > 50000 then
            alerts[#alerts + 1] = {
                type = "LARGE_POST_BODY",
                url = req.url,
                body_size = req.body_size,
                severity = "MEDIUM",
                description = string.format(
                    "Requisição POST com corpo grande (%d bytes) para %s",
                    req.body_size, req.url
                ),
            }
        end
    end

    if self.logger and #alerts > 0 then
        self.logger:warn("NETWORK", string.format(
            "Análise de tráfego: %d alertas gerados", #alerts
        ))
    end

    return alerts
end

--- Retorna o log de requisições
--- @return table
function NetworkMonitor:getRequestLog()
    return self.requestLog
end

--- Retorna requisições bloqueadas/suspeitas
--- @return table
function NetworkMonitor:getBlockedRequests()
    return self.blockedRequests
end

--- Retorna estatísticas
--- @return table
function NetworkMonitor:getStats()
    return self.stats
end

--- Exporta dados do monitor como JSON
--- @return string JSON formatado
function NetworkMonitor:exportJSON()
    local data = {
        export_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        stats = self.stats,
        alerts = self:analyzeTraffic(),
        request_log = self.requestLog,
        blocked_requests = self.blockedRequests,
    }
    return JSON.encodePretty(data)
end

--- Limpa todos os registros
function NetworkMonitor:reset()
    self.requestLog = {}
    self.blockedRequests = {}
    self.stats = {
        total_requests = 0,
        blocked_requests = 0,
        suspicious_requests = 0,
        by_method = {},
        by_domain = {},
    }
end

return NetworkMonitor
