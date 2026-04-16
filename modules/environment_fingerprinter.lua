--[[
    Scanning-Lua - Environment Fingerprinter Module
    Identifica o executor em uso, suas capacidades e possíveis riscos
    Faz fingerprint do ambiente de execução para análise de segurança
]]

local EnvironmentFingerprinter = {}
EnvironmentFingerprinter.__index = EnvironmentFingerprinter

--- Cria uma nova instância do fingerprinter
--- @param logger table Instância do Logger
--- @return table EnvironmentFingerprinter instance
function EnvironmentFingerprinter.new(logger)
    local self = setmetatable({}, EnvironmentFingerprinter)
    self.logger = logger
    self.fingerprint = {}
    self.capabilities = {}
    self.riskFactors = {}
    return self
end

--- Executa fingerprint completo do ambiente
--- @return table Resultado do fingerprint
function EnvironmentFingerprinter:scan()
    if self.logger then
        self.logger:info("ENV", "Iniciando fingerprint do ambiente")
    end

    self.fingerprint = {
        scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        executor = self:_detectExecutor(),
        lua_version = self:_getLuaVersion(),
        capabilities = self:_scanCapabilities(),
        globals = self:_scanGlobals(),
        services = self:_scanServices(),
        risk_assessment = {},
    }

    self.fingerprint.risk_assessment = self:_assessRisks()

    if self.logger then
        self.logger:info("ENV", "Fingerprint concluído", {
            executor = self.fingerprint.executor.name,
            capabilities_count = self.fingerprint.capabilities.total,
            risk_level = self.fingerprint.risk_assessment.level,
        })
    end

    return self.fingerprint
end

--- Detecta o executor em uso
--- @return table Informações do executor
function EnvironmentFingerprinter:_detectExecutor()
    local executor = {
        name = "Unknown",
        version = "Unknown",
        platform = "Unknown",
    }

    -- Wave
    local ok = pcall(function()
        if wave or Wave or WAVE then
            executor.name = "Wave"
            pcall(function()
                local w = wave or Wave or WAVE
                if w.version then executor.version = tostring(w.version) end
            end)
        end
    end)

    -- Synapse X
    if executor.name == "Unknown" then
        pcall(function()
            if syn and syn.protect_gui then
                executor.name = "Synapse X"
                if syn.about then
                    local info = syn.about()
                    executor.version = info and info.version or "Unknown"
                end
            end
        end)
    end

    -- Script-Ware
    if executor.name == "Unknown" then
        pcall(function()
            if SW_LOADED or isourclosure then
                executor.name = "Script-Ware"
            end
        end)
    end

    -- Fluxus
    if executor.name == "Unknown" then
        pcall(function()
            if fluxus or FLUXUS_FOLDER then
                executor.name = "Fluxus"
            end
        end)
    end

    -- KRNL
    if executor.name == "Unknown" then
        pcall(function()
            if KRNL_LOADED or krnl then
                executor.name = "KRNL"
            end
        end)
    end

    -- Electron
    if executor.name == "Unknown" then
        pcall(function()
            if Electron then
                executor.name = "Electron"
            end
        end)
    end

    -- Genérico — detectar por funções disponíveis
    if executor.name == "Unknown" then
        pcall(function()
            if getexecutorname then
                executor.name = getexecutorname()
            elseif identifyexecutor then
                executor.name = identifyexecutor()
            end
        end)
    end

    -- Plataforma
    pcall(function()
        if game and game.PlaceId then
            executor.platform = "Roblox"
            executor.place_id = game.PlaceId
            executor.game_id = game.GameId
        end
    end)

    -- Se não detectou nada, pode ser Lua padrão
    if executor.name == "Unknown" then
        pcall(function()
            if not game and _VERSION then
                executor.name = "Lua Standalone"
                executor.version = _VERSION
                executor.platform = "Desktop"
            end
        end)
    end

    return executor
end

--- Obtém versão do Lua
--- @return table Informações da versão
function EnvironmentFingerprinter:_getLuaVersion()
    return {
        version = _VERSION or "Unknown",
        jit = jit and jit.version or nil,
        jit_os = jit and jit.os or nil,
        jit_arch = jit and jit.arch or nil,
    }
end

--- Escaneia capacidades disponíveis no executor
--- @return table Lista de capacidades
function EnvironmentFingerprinter:_scanCapabilities()
    local caps = {
        total = 0,
        filesystem = {},
        hooking = {},
        debug_lib = {},
        network = {},
        execution = {},
        ui = {},
        misc = {},
    }

    -- Filesystem
    local fsFuncs = {
        "readfile", "writefile", "appendfile", "loadfile",
        "listfiles", "isfile", "isfolder", "makefolder",
        "delfolder", "delfile",
    }
    for _, fn in ipairs(fsFuncs) do
        local exists = pcall(function() return type(_G[fn]) == "function" end)
        if exists and type(_G[fn]) == "function" then
            caps.filesystem[#caps.filesystem + 1] = fn
            caps.total = caps.total + 1
        end
    end

    -- Hooking
    local hookFuncs = {
        "hookfunction", "hookmetamethod", "newcclosure",
        "replaceclosure", "iscclosure", "islclosure",
        "clonefunction", "getnamecallmethod", "setnamecallmethod",
    }
    for _, fn in ipairs(hookFuncs) do
        local exists = false
        pcall(function() exists = type(_G[fn]) == "function" end)
        if exists then
            caps.hooking[#caps.hooking + 1] = fn
            caps.total = caps.total + 1
        end
    end

    -- Debug library
    local debugFuncs = {
        "debug.getupvalue", "debug.setupvalue", "debug.getinfo",
        "debug.getconstant", "debug.setconstant", "debug.getlocal",
        "debug.setlocal", "debug.getregistry",
    }
    for _, fn in ipairs(debugFuncs) do
        local parts = {}
        for part in fn:gmatch("[^.]+") do parts[#parts + 1] = part end
        local exists = false
        pcall(function()
            if #parts == 2 and _G[parts[1]] then
                exists = type(_G[parts[1]][parts[2]]) == "function"
            end
        end)
        if exists then
            caps.debug_lib[#caps.debug_lib + 1] = fn
            caps.total = caps.total + 1
        end
    end

    -- Network
    local netFuncs = { "request", "http_request", "syn.request", "HttpGet", "HttpPost" }
    for _, fn in ipairs(netFuncs) do
        local exists = false
        pcall(function()
            if fn:find("%.") then
                local parts = {}
                for part in fn:gmatch("[^.]+") do parts[#parts + 1] = part end
                exists = type(_G[parts[1]][parts[2]]) == "function"
            else
                exists = type(_G[fn]) == "function"
            end
        end)
        if exists then
            caps.network[#caps.network + 1] = fn
            caps.total = caps.total + 1
        end
    end

    -- Execution
    local execFuncs = {
        "loadstring", "getgenv", "getrenv", "getfenv", "setfenv",
        "getrawmetatable", "setrawmetatable", "setreadonly",
        "decompile", "saveinstance",
    }
    for _, fn in ipairs(execFuncs) do
        local exists = false
        pcall(function() exists = type(_G[fn]) == "function" end)
        if exists then
            caps.execution[#caps.execution + 1] = fn
            caps.total = caps.total + 1
        end
    end

    -- UI
    local uiFuncs = {
        "Drawing.new", "gethui", "protectgui", "syn.protect_gui",
    }
    for _, fn in ipairs(uiFuncs) do
        local exists = false
        pcall(function()
            if fn:find("%.") then
                local parts = {}
                for part in fn:gmatch("[^.]+") do parts[#parts + 1] = part end
                if _G[parts[1]] then
                    exists = type(_G[parts[1]][parts[2]]) == "function"
                end
            else
                exists = type(_G[fn]) == "function"
            end
        end)
        if exists then
            caps.ui[#caps.ui + 1] = fn
            caps.total = caps.total + 1
        end
    end

    -- Misc
    local miscFuncs = {
        "fireclickdetector", "firetouchinterest", "fireproximityprompt",
        "firesignal", "getconnections", "getinstances", "getnilinstances",
        "getscripts", "getrunningscripts", "getloadedmodules",
        "getreg", "getgc", "getthreadidentity", "setthreadidentity",
    }
    for _, fn in ipairs(miscFuncs) do
        local exists = false
        pcall(function() exists = type(_G[fn]) == "function" end)
        if exists then
            caps.misc[#caps.misc + 1] = fn
            caps.total = caps.total + 1
        end
    end

    return caps
end

--- Escaneia globais disponíveis
--- @return table Lista de globais relevantes
function EnvironmentFingerprinter:_scanGlobals()
    local globals = {}
    local safeGlobals = {
        "print", "warn", "error", "type", "typeof", "tostring", "tonumber",
        "pairs", "ipairs", "next", "select", "unpack", "pcall", "xpcall",
        "rawget", "rawset", "rawequal", "rawlen", "setmetatable", "getmetatable",
        "string", "table", "math", "coroutine", "os", "io", "debug",
        "true", "false", "nil", "_VERSION",
    }

    local safeSet = {}
    for _, g in ipairs(safeGlobals) do safeSet[g] = true end

    local count = 0
    pcall(function()
        local env = getgenv and getgenv() or _G
        for k, v in pairs(env) do
            if type(k) == "string" and not safeSet[k] then
                count = count + 1
                if count <= 100 then -- Limitar output
                    globals[#globals + 1] = {
                        name = k,
                        type = type(v),
                    }
                end
            end
        end
    end)

    return {
        total_non_standard = count,
        sample = globals,
    }
end

--- Escaneia serviços Roblox disponíveis
--- @return table Lista de serviços acessíveis
function EnvironmentFingerprinter:_scanServices()
    local services = {}
    local serviceNames = {
        "Players", "Workspace", "ReplicatedStorage", "ReplicatedFirst",
        "ServerScriptService", "ServerStorage", "Lighting",
        "StarterGui", "StarterPack", "StarterPlayer",
        "HttpService", "DataStoreService", "MarketplaceService",
        "TeleportService", "BadgeService", "MessagingService",
        "UserInputService", "RunService", "TweenService",
        "SoundService", "Chat", "Teams", "TestService",
        "InsertService", "GamePassService",
    }

    for _, svcName in ipairs(serviceNames) do
        local accessible = false
        pcall(function()
            if game and game.GetService then
                local svc = game:GetService(svcName)
                accessible = svc ~= nil
            end
        end)
        services[#services + 1] = {
            name = svcName,
            accessible = accessible,
        }
    end

    return services
end

--- Avalia riscos baseado no fingerprint
--- @return table Avaliação de risco
function EnvironmentFingerprinter:_assessRisks()
    local risks = {}
    local riskScore = 0

    local caps = self.fingerprint.capabilities or {}

    -- Hooking disponível = alto risco
    if caps.hooking and #caps.hooking > 0 then
        risks[#risks + 1] = {
            risk = "HOOKING_AVAILABLE",
            severity = "HIGH",
            description = string.format(
                "%d funções de hooking disponíveis - código pode ser interceptado",
                #caps.hooking
            ),
            functions = caps.hooking,
        }
        riskScore = riskScore + 30
    end

    -- Debug library disponível
    if caps.debug_lib and #caps.debug_lib > 0 then
        risks[#risks + 1] = {
            risk = "DEBUG_LIBRARY_EXPOSED",
            severity = "HIGH",
            description = string.format(
                "%d funções debug expostas - memória pode ser manipulada",
                #caps.debug_lib
            ),
            functions = caps.debug_lib,
        }
        riskScore = riskScore + 25
    end

    -- Funções de execução
    if caps.execution and #caps.execution > 3 then
        risks[#risks + 1] = {
            risk = "EXECUTION_FUNCTIONS_AVAILABLE",
            severity = "CRITICAL",
            description = string.format(
                "%d funções de execução disponíveis - alto risco de injeção",
                #caps.execution
            ),
            functions = caps.execution,
        }
        riskScore = riskScore + 40
    end

    -- Filesystem
    if caps.filesystem and #caps.filesystem > 0 then
        risks[#risks + 1] = {
            risk = "FILESYSTEM_ACCESS",
            severity = "MEDIUM",
            description = string.format(
                "%d funções de filesystem disponíveis",
                #caps.filesystem
            ),
            functions = caps.filesystem,
        }
        riskScore = riskScore + 15
    end

    -- Determinar nível geral
    local level = "LOW"
    if riskScore >= 80 then level = "CRITICAL"
    elseif riskScore >= 50 then level = "HIGH"
    elseif riskScore >= 25 then level = "MEDIUM"
    end

    return {
        level = level,
        score = riskScore,
        risks = risks,
    }
end

--- Retorna o fingerprint atual
--- @return table
function EnvironmentFingerprinter:getFingerprint()
    return self.fingerprint
end

--- Retorna as capacidades detectadas
--- @return table
function EnvironmentFingerprinter:getCapabilities()
    return self.fingerprint.capabilities or {}
end

return EnvironmentFingerprinter
