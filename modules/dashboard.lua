--[[
    Scanning-Lua - Dashboard Module (#21)
    Dashboard para exibir resultados de análise

    Exibe:
    - Scripts analisados
    - Riscos encontrados
    - Estatísticas formatadas
    - Suporte a console e webhook
]]

local Dashboard = {}
Dashboard.__index = Dashboard

--- Cria uma nova instância do dashboard
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table Dashboard instance
function Dashboard.new(config, logger)
    local self = setmetatable({}, Dashboard)
    self.config = config or {}
    self.logger = logger
    self.sections = {}
    self.lastRefresh = nil
    return self
end

--- Gera e exibe dashboard completo no console
--- @param stats table Estatísticas coletadas de todos os módulos
function Dashboard:displayConsole(stats)
    stats = stats or {}
    local lines = {}

    -- Header
    lines[#lines + 1] = ""
    lines[#lines + 1] = "╔══════════════════════════════════════════════════════════════╗"
    lines[#lines + 1] = "║              🔒 Scanning-Lua Dashboard                      ║"
    lines[#lines + 1] = "║                    v3.0.0 Advanced                           ║"
    lines[#lines + 1] = "╚══════════════════════════════════════════════════════════════╝"
    lines[#lines + 1] = ""

    -- Seção: Scan Overview
    lines[#lines + 1] = "┌─── 📊 Scan Overview ───────────────────────────────────────┐"
    local scanner = stats.scanner or {}
    lines[#lines + 1] = string.format("│  Scripts Analisados:    %d", scanner.scripts_analyzed or 0)
    lines[#lines + 1] = string.format("│  RemoteEvents:          %d", scanner.remote_events or 0)
    lines[#lines + 1] = string.format("│  RemoteFunctions:       %d", scanner.remote_functions or 0)
    lines[#lines + 1] = string.format("│  Itens Suspeitos:       %d", scanner.suspicious_items or 0)
    lines[#lines + 1] = "└────────────────────────────────────────────────────────────┘"
    lines[#lines + 1] = ""

    -- Seção: Vulnerabilidades
    lines[#lines + 1] = "┌─── 🛡️ Vulnerabilidades ───────────────────────────────────┐"
    local vuln = stats.vulnerabilities or {}
    local bySev = vuln.by_severity or {}
    lines[#lines + 1] = string.format("│  Total:      %d", vuln.total_detected or 0)
    lines[#lines + 1] = string.format("│  ⚫ CRITICAL: %d", bySev.CRITICAL or 0)
    lines[#lines + 1] = string.format("│  🔴 HIGH:     %d", bySev.HIGH or 0)
    lines[#lines + 1] = string.format("│  🟠 MEDIUM:   %d", bySev.MEDIUM or 0)
    lines[#lines + 1] = string.format("│  🟡 LOW:      %d", bySev.LOW or 0)
    lines[#lines + 1] = "└────────────────────────────────────────────────────────────┘"
    lines[#lines + 1] = ""

    -- Seção: Heuristic Score
    local heuristic = stats.heuristic or {}
    if heuristic.total_analyzed then
        lines[#lines + 1] = "┌─── 🧠 Heuristic Analysis ──────────────────────────────────┐"
        lines[#lines + 1] = string.format("│  Analisados:    %d", heuristic.total_analyzed or 0)
        lines[#lines + 1] = string.format("│  Score Máximo:  %d", heuristic.max_score or 0)
        lines[#lines + 1] = string.format("│  Score Médio:   %.1f", heuristic.average_score or 0)
        local hByLevel = heuristic.by_level or {}
        lines[#lines + 1] = string.format("│  CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d",
            hByLevel.CRITICAL or 0, hByLevel.HIGH or 0,
            hByLevel.MEDIUM or 0, hByLevel.LOW or 0)
        lines[#lines + 1] = "└────────────────────────────────────────────────────────────┘"
        lines[#lines + 1] = ""
    end

    -- Seção: Signatures
    local sigs = stats.signatures or {}
    if sigs.total_scanned then
        lines[#lines + 1] = "┌─── 🧩 Signature Detections ────────────────────────────────┐"
        lines[#lines + 1] = string.format("│  Scripts Escaneados: %d", sigs.total_scanned or 0)
        lines[#lines + 1] = string.format("│  Detecções:          %d", sigs.total_detections or 0)
        lines[#lines + 1] = "└────────────────────────────────────────────────────────────┘"
        lines[#lines + 1] = ""
    end

    -- Seção: Behavior
    local behavior = stats.behavior or {}
    if behavior.total_alerts then
        lines[#lines + 1] = "┌─── 🧠 Behavior Analysis ───────────────────────────────────┐"
        lines[#lines + 1] = string.format("│  Alertas:            %d", behavior.total_alerts or 0)
        lines[#lines + 1] = string.format("│  Instâncias Criadas: %d", behavior.total_instances_created or 0)
        lines[#lines + 1] = string.format("│  Remote Calls:       %d", behavior.total_remote_calls or 0)
        lines[#lines + 1] = "└────────────────────────────────────────────────────────────┘"
        lines[#lines + 1] = ""
    end

    -- Seção: Network
    local network = stats.network or {}
    if network.total_requests then
        lines[#lines + 1] = "┌─── 📡 Network Monitor ─────────────────────────────────────┐"
        lines[#lines + 1] = string.format("│  Requisições Total:    %d", network.total_requests or 0)
        lines[#lines + 1] = string.format("│  Requisições Suspeitas:%d", network.suspicious_requests or 0)
        lines[#lines + 1] = "└────────────────────────────────────────────────────────────┘"
        lines[#lines + 1] = ""
    end

    -- Seção: Incremental Cache
    local incremental = stats.incremental or {}
    if incremental.total_checks then
        lines[#lines + 1] = "┌─── 🔍 Incremental Scanner ─────────────────────────────────┐"
        lines[#lines + 1] = string.format("│  Cache Hit Rate:     %d%%", incremental.cache_hit_rate or 0)
        lines[#lines + 1] = string.format("│  Scripts Rastreados: %d", incremental.scripts_tracked or 0)
        lines[#lines + 1] = string.format("│  Re-scans:           %d", incremental.rescans or 0)
        lines[#lines + 1] = "└────────────────────────────────────────────────────────────┘"
        lines[#lines + 1] = ""
    end

    -- Seção: Performance
    local perf = stats.performance or {}
    if perf.events_logged then
        lines[#lines + 1] = "┌─── ⚡ Performance ──────────────────────────────────────────┐"
        lines[#lines + 1] = string.format("│  Eventos Debug:      %d", perf.events_logged or 0)
        lines[#lines + 1] = string.format("│  Verbose Mode:       %s", perf.verbose_mode and "ON" or "OFF")
        lines[#lines + 1] = "└────────────────────────────────────────────────────────────┘"
        lines[#lines + 1] = ""
    end

    -- Risk Bar
    lines[#lines + 1] = self:_generateRiskBar(stats)
    lines[#lines + 1] = ""

    -- Footer
    lines[#lines + 1] = "──────────────────────────────────────────────────────────────"
    lines[#lines + 1] = string.format("  Generated: %s", os.date("!%Y-%m-%d %H:%M:%S UTC"))
    lines[#lines + 1] = "──────────────────────────────────────────────────────────────"
    lines[#lines + 1] = ""

    -- Imprimir todas as linhas
    local output = table.concat(lines, "\n")
    print(output)

    self.lastRefresh = os.time()
    return output
end

--- Gera barra de risco visual
--- @param stats table Estatísticas
--- @return string
function Dashboard:_generateRiskBar(stats)
    local vuln = stats.vulnerabilities or {}
    local bySev = vuln.by_severity or {}

    local totalVuln = (bySev.CRITICAL or 0) + (bySev.HIGH or 0) +
        (bySev.MEDIUM or 0) + (bySev.LOW or 0)

    local riskLevel = "NONE"
    local bar = "██████████████████████████████"
    local color = "🟢"

    if (bySev.CRITICAL or 0) > 0 then
        riskLevel = "CRITICAL"
        bar = "██████████████████████████████"
        color = "⚫"
    elseif (bySev.HIGH or 0) > 0 then
        riskLevel = "HIGH"
        bar = "████████████████████████      "
        color = "🔴"
    elseif (bySev.MEDIUM or 0) > 0 then
        riskLevel = "MEDIUM"
        bar = "████████████████              "
        color = "🟠"
    elseif (bySev.LOW or 0) > 0 then
        riskLevel = "LOW"
        bar = "████████                      "
        color = "🟡"
    end

    return string.format("  Risk Level: %s %s [%s] (%d vulnerabilities)",
        color, riskLevel, bar, totalVuln)
end

--- Gera dados para webhook Discord
--- @param stats table Estatísticas
--- @return table Embed para Discord
function Dashboard:generateWebhookEmbed(stats)
    stats = stats or {}
    local vuln = stats.vulnerabilities or {}
    local bySev = vuln.by_severity or {}
    local scanner = stats.scanner or {}

    local colorMap = {
        CRITICAL = 15158332,
        HIGH = 15105570,
        MEDIUM = 16776960,
        LOW = 3447003,
        NONE = 3066993,
    }

    local riskLevel = "NONE"
    if (bySev.CRITICAL or 0) > 0 then riskLevel = "CRITICAL"
    elseif (bySev.HIGH or 0) > 0 then riskLevel = "HIGH"
    elseif (bySev.MEDIUM or 0) > 0 then riskLevel = "MEDIUM"
    elseif (bySev.LOW or 0) > 0 then riskLevel = "LOW" end

    local embed = {
        title = "🔒 Scanning-Lua Dashboard",
        color = colorMap[riskLevel] or colorMap.NONE,
        fields = {
            { name = "📊 Scripts", value = tostring(scanner.scripts_analyzed or 0), inline = true },
            { name = "🛡️ Vulnerabilities", value = tostring(vuln.total_detected or 0), inline = true },
            { name = "⚠️ Risk Level", value = riskLevel, inline = true },
            { name = "CRITICAL", value = tostring(bySev.CRITICAL or 0), inline = true },
            { name = "HIGH", value = tostring(bySev.HIGH or 0), inline = true },
            { name = "MEDIUM", value = tostring(bySev.MEDIUM or 0), inline = true },
        },
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        footer = { text = "Scanning-Lua v3.0.0 Advanced" },
    }

    -- Adicionar heuristic info
    local heuristic = stats.heuristic or {}
    if heuristic.max_score then
        embed.fields[#embed.fields + 1] = {
            name = "🧠 Max Score",
            value = tostring(heuristic.max_score),
            inline = true,
        }
    end

    return embed
end

--- Gera relatório resumido como tabela
--- @param stats table Estatísticas
--- @return table Relatório estruturado
function Dashboard:generateReport(stats)
    return {
        generated_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        scanner = stats.scanner or {},
        vulnerabilities = stats.vulnerabilities or {},
        heuristic = stats.heuristic or {},
        signatures = stats.signatures or {},
        behavior = stats.behavior or {},
        network = stats.network or {},
        incremental = stats.incremental or {},
        performance = stats.performance or {},
    }
end

return Dashboard
