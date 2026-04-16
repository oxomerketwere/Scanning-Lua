--[[
    Scanning-Lua - Discord Webhook Module
    Envia alertas e relatórios para Discord via webhook
    Permite monitoramento remoto em tempo real
]]

local DiscordWebhook = {}
DiscordWebhook.__index = DiscordWebhook

--- Cria uma nova instância do módulo Discord
--- @param webhookUrl string|nil URL do webhook Discord
--- @param logger table Instância do Logger
--- @return table DiscordWebhook instance
function DiscordWebhook.new(webhookUrl, logger)
    local self = setmetatable({}, DiscordWebhook)
    self.webhookUrl = webhookUrl
    self.logger = logger
    self.enabled = webhookUrl ~= nil and webhookUrl ~= ""
    self.messageQueue = {}
    self.sentCount = 0
    return self
end

--- Define a URL do webhook
--- @param url string URL do webhook Discord
function DiscordWebhook:setWebhookUrl(url)
    self.webhookUrl = url
    self.enabled = url ~= nil and url ~= ""
end

--- Envia uma mensagem para o Discord
--- @param content string Conteúdo da mensagem
--- @param embeds table|nil Lista de embeds
--- @return boolean success
function DiscordWebhook:send(content, embeds)
    if not self.enabled then return false end

    local payload = {}
    if content then payload.content = content end
    if embeds then payload.embeds = embeds end

    local success = false

    -- Tentar syn.request primeiro (Synapse/Wave)
    pcall(function()
        if syn and syn.request then
            syn.request({
                Url = self.webhookUrl,
                Method = "POST",
                Headers = { ["Content-Type"] = "application/json" },
                Body = self:_encodeJSON(payload),
            })
            success = true
        end
    end)

    -- Fallback: http_request
    if not success then
        pcall(function()
            if http_request then
                http_request({
                    Url = self.webhookUrl,
                    Method = "POST",
                    Headers = { ["Content-Type"] = "application/json" },
                    Body = self:_encodeJSON(payload),
                })
                success = true
            end
        end)
    end

    -- Fallback: request
    if not success then
        pcall(function()
            if request then
                request({
                    Url = self.webhookUrl,
                    Method = "POST",
                    Headers = { ["Content-Type"] = "application/json" },
                    Body = self:_encodeJSON(payload),
                })
                success = true
            end
        end)
    end

    -- Fallback: HttpService (dentro do Roblox)
    if not success then
        pcall(function()
            if game then
                local HttpService = game:GetService("HttpService")
                HttpService:PostAsync(self.webhookUrl, self:_encodeJSON(payload))
                success = true
            end
        end)
    end

    if success then
        self.sentCount = self.sentCount + 1
        if self.logger then
            self.logger:debug("DISCORD", "Mensagem enviada com sucesso")
        end
    end

    return success
end

--- Envia um alerta de vulnerabilidade
--- @param vuln table Dados da vulnerabilidade
function DiscordWebhook:sendVulnerabilityAlert(vuln)
    if not self.enabled then return end

    local colorMap = {
        CRITICAL = 15158332, -- Vermelho
        HIGH = 15105570,     -- Laranja
        MEDIUM = 16776960,   -- Amarelo
        LOW = 3447003,       -- Verde
    }

    local embed = {
        title = "🔒 Vulnerabilidade Detectada",
        color = colorMap[vuln.severity] or 8421504,
        fields = {
            { name = "ID", value = vuln.vuln_id or "N/A", inline = true },
            { name = "Severidade", value = vuln.severity or "N/A", inline = true },
            { name = "Categoria", value = vuln.category or "N/A", inline = true },
            { name = "Nome", value = vuln.name or "N/A", inline = false },
            { name = "Descrição", value = vuln.description or "N/A", inline = false },
            { name = "Origem", value = vuln.source or "N/A", inline = true },
            { name = "Remediação", value = vuln.remediation or "N/A", inline = false },
        },
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        footer = { text = "Scanning-Lua v1.0.0" },
    }

    if vuln.line_number then
        embed.fields[#embed.fields + 1] = {
            name = "Linha",
            value = tostring(vuln.line_number),
            inline = true,
        }
    end

    self:send(nil, { embed })
end

--- Envia resumo do scan
--- @param summary table Resumo do scan
function DiscordWebhook:sendScanSummary(summary)
    if not self.enabled then return end

    local vulnStats = summary.vulnerability_stats or {}
    local severity = vulnStats.by_severity or {}
    local scanResults = summary.scan_results or {}

    local riskEmoji = "✅"
    if (severity.CRITICAL or 0) > 0 then riskEmoji = "🔴"
    elseif (severity.HIGH or 0) > 0 then riskEmoji = "🟠"
    elseif (severity.MEDIUM or 0) > 0 then riskEmoji = "🟡"
    end

    local embed = {
        title = riskEmoji .. " Resumo do Scan",
        color = 3447003,
        fields = {
            { name = "Scripts Analisados", value = tostring(scanResults.scripts_analyzed or 0), inline = true },
            { name = "RemoteEvents", value = tostring(scanResults.remote_events or 0), inline = true },
            { name = "RemoteFunctions", value = tostring(scanResults.remote_functions or 0), inline = true },
            { name = "Itens Suspeitos", value = tostring(scanResults.suspicious_items or 0), inline = true },
            { name = "Vulnerabilidades", value = tostring(vulnStats.total_detected or 0), inline = true },
            { name = "CRITICAL", value = tostring(severity.CRITICAL or 0), inline = true },
            { name = "HIGH", value = tostring(severity.HIGH or 0), inline = true },
            { name = "MEDIUM", value = tostring(severity.MEDIUM or 0), inline = true },
            { name = "LOW", value = tostring(severity.LOW or 0), inline = true },
        },
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        footer = { text = "Scanning-Lua v1.0.0" },
    }

    -- Adicionar info do jogo se disponível
    pcall(function()
        if game and game.PlaceId then
            embed.fields[#embed.fields + 1] = {
                name = "Place ID",
                value = tostring(game.PlaceId),
                inline = true,
            }
        end
    end)

    self:send(nil, { embed })
end

--- Codifica tabela para JSON (versão simplificada inline)
--- @param value any Valor a codificar
--- @return string JSON
function DiscordWebhook:_encodeJSON(value)
    -- Tenta usar HttpService se disponível
    local jsonStr
    pcall(function()
        if game then
            local HttpService = game:GetService("HttpService")
            jsonStr = HttpService:JSONEncode(value)
        end
    end)
    if jsonStr then return jsonStr end

    -- Fallback: encoder manual simplificado
    return DiscordWebhook._manualEncode(value)
end

--- Encoder JSON manual simplificado
function DiscordWebhook._manualEncode(value)
    local t = type(value)
    if value == nil then return "null"
    elseif t == "boolean" then return tostring(value)
    elseif t == "number" then
        if value ~= value then return "null" end
        return tostring(value)
    elseif t == "string" then
        local escaped = value:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r'):gsub('\t', '\\t')
        return '"' .. escaped .. '"'
    elseif t == "table" then
        -- Verificar se é array
        local isArr = true
        local count = 0
        for _ in pairs(value) do count = count + 1 end
        for i = 1, count do
            if value[i] == nil then isArr = false; break end
        end
        if count == 0 then isArr = true end

        local parts = {}
        if isArr and count > 0 then
            for i = 1, #value do
                parts[#parts + 1] = DiscordWebhook._manualEncode(value[i])
            end
            return "[" .. table.concat(parts, ",") .. "]"
        else
            for k, v in pairs(value) do
                if type(k) == "string" or type(k) == "number" then
                    parts[#parts + 1] = '"' .. tostring(k) .. '":' .. DiscordWebhook._manualEncode(v)
                end
            end
            return "{" .. table.concat(parts, ",") .. "}"
        end
    end
    return "null"
end

--- Retorna estatísticas
--- @return table
function DiscordWebhook:getStats()
    return {
        enabled = self.enabled,
        messages_sent = self.sentCount,
    }
end

return DiscordWebhook
