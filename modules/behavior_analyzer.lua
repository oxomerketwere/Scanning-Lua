--[[
    Scanning-Lua - Behavior Analyzer Module (#11)
    Analisa o comportamento de scripts em RUNTIME
    Em vez de só analisar código estático, observa o que o script FAZ

    Detecta:
    - Criação excessiva de RemoteEvents
    - Chamadas FireServer em loop
    - Criação de GUIs invisíveis (possível backdoor)
    - Padrões de criação de instâncias suspeitas
]]

local BehaviorAnalyzer = {}
BehaviorAnalyzer.__index = BehaviorAnalyzer

--- Cria uma nova instância do analisador de comportamento
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table BehaviorAnalyzer instance
function BehaviorAnalyzer.new(config, logger)
    local self = setmetatable({}, BehaviorAnalyzer)
    self.config = config or {}
    self.logger = logger
    self.hooks = {}
    self.instanceCreations = {}
    self.remoteCalls = {}
    self.guiCreations = {}
    self.alerts = {}
    self.isMonitoring = false
    self.stats = {
        total_instances_created = 0,
        total_remote_calls = 0,
        total_gui_creations = 0,
        total_alerts = 0,
        by_class = {},
        by_remote = {},
    }

    -- Thresholds configuráveis
    self.thresholds = {
        max_remote_creations = config.MAX_REMOTE_CREATIONS or 10,
        max_fire_server_per_minute = config.MAX_FIRE_SERVER_PER_MINUTE or 30,
        max_invisible_guis = config.MAX_INVISIBLE_GUIS or 3,
        max_instance_burst = config.MAX_INSTANCE_BURST or 50,
        burst_window_seconds = config.BURST_WINDOW_SECONDS or 5,
    }

    return self
end

--- Inicia o monitoramento de comportamento em runtime
function BehaviorAnalyzer:startMonitoring()
    if self.isMonitoring then return end
    self.isMonitoring = true

    if self.logger then
        self.logger:info("BEHAVIOR", "Iniciando monitoramento de comportamento runtime")
    end

    self:_hookInstanceNew()
    self:_hookFireServer()
    self:_monitorGUICreation()
end

--- Para o monitoramento
function BehaviorAnalyzer:stopMonitoring()
    self.isMonitoring = false

    -- Restaurar hooks
    for name, original in pairs(self.hooks) do
        pcall(function()
            if hookfunction and original.hooked and original.original then
                hookfunction(original.hooked, original.original)
            end
        end)
    end
    self.hooks = {}

    if self.logger then
        self.logger:info("BEHAVIOR", "Monitoramento de comportamento encerrado", self:getStats())
    end
end

--- Hook em Instance.new para monitorar criação de instâncias
function BehaviorAnalyzer:_hookInstanceNew()
    local selfRef = self

    pcall(function()
        if not hookfunction or not Instance or not Instance.new then return end

        local originalNew = hookfunction(Instance.new, function(className, parent, ...)
            local instance = originalNew(className, parent, ...)
            selfRef:_recordInstanceCreation(className, parent)
            return instance
        end)

        selfRef.hooks.instanceNew = {
            original = originalNew,
            hooked = Instance.new,
        }

        if selfRef.logger then
            selfRef.logger:info("BEHAVIOR", "Hook Instance.new instalado")
        end
    end)
end

--- Hook em FireServer para monitorar chamadas de remote
function BehaviorAnalyzer:_hookFireServer()
    local selfRef = self

    pcall(function()
        if not hookfunction or not game then return end

        -- Hook via metatable namecall
        local mt = getrawmetatable and getrawmetatable(game)
        if not mt then return end

        local oldNamecall = mt.__namecall
        if not oldNamecall then return end

        local setReadonly = setreadonly or function() end
        setReadonly(mt, false)

        local newNamecall = newcclosure and newcclosure(function(self_ref, ...)
            local method = getnamecallmethod and getnamecallmethod()
            if method == "FireServer" or method == "InvokeServer" then
                selfRef:_recordRemoteCall(self_ref, method, {...})
            end
            return oldNamecall(self_ref, ...)
        end) or nil

        if newNamecall then
            mt.__namecall = newNamecall
            selfRef.hooks.namecall = {
                original = oldNamecall,
                hooked = newNamecall,
            }
        end

        setReadonly(mt, true)

        if selfRef.logger then
            selfRef.logger:info("BEHAVIOR", "Hook FireServer/InvokeServer instalado")
        end
    end)
end

--- Monitorar criação de GUIs (especialmente invisíveis)
function BehaviorAnalyzer:_monitorGUICreation()
    local selfRef = self

    pcall(function()
        if not game or not game.GetService then return end

        local playerGui
        pcall(function()
            local Players = game:GetService("Players")
            local localPlayer = Players.LocalPlayer
            if localPlayer then
                playerGui = localPlayer:FindFirstChild("PlayerGui")
            end
        end)

        if playerGui and playerGui.ChildAdded then
            local conn = playerGui.ChildAdded:Connect(function(child)
                selfRef:_recordGUICreation(child)
            end)
            selfRef.hooks.guiMonitor = { connection = conn }
        end
    end)
end

--- Registra uma criação de instância
--- @param className string Classe da instância criada
--- @param parent any Parent da instância
function BehaviorAnalyzer:_recordInstanceCreation(className, parent)
    local now = os.time()
    local entry = {
        class = className,
        parent = parent and tostring(parent) or "nil",
        timestamp = now,
    }

    self.instanceCreations[#self.instanceCreations + 1] = entry
    self.stats.total_instances_created = self.stats.total_instances_created + 1
    self.stats.by_class[className] = (self.stats.by_class[className] or 0) + 1

    -- Detectar criação excessiva de RemoteEvents
    if className == "RemoteEvent" or className == "RemoteFunction" then
        local remoteCount = self.stats.by_class[className]
        if remoteCount >= self.thresholds.max_remote_creations then
            self:_createAlert("EXCESSIVE_REMOTE_CREATION", "HIGH", {
                class = className,
                count = remoteCount,
                threshold = self.thresholds.max_remote_creations,
                description = string.format(
                    "%d %s criados - comportamento suspeito (possível backdoor)",
                    remoteCount, className
                ),
            })
        end
    end

    -- Detectar burst de criação de instâncias
    self:_checkInstanceBurst(now)
end

--- Verifica burst de criação de instâncias
--- @param now number Timestamp atual
function BehaviorAnalyzer:_checkInstanceBurst(now)
    local window = self.thresholds.burst_window_seconds
    local threshold = self.thresholds.max_instance_burst

    -- Contar instâncias criadas na janela
    local count = 0
    for i = #self.instanceCreations, 1, -1 do
        local entry = self.instanceCreations[i]
        if now - entry.timestamp <= window then
            count = count + 1
        else
            break
        end
    end

    if count >= threshold then
        self:_createAlert("INSTANCE_CREATION_BURST", "MEDIUM", {
            count = count,
            window_seconds = window,
            threshold = threshold,
            description = string.format(
                "%d instâncias criadas em %d segundos - possível atividade maliciosa",
                count, window
            ),
        })
    end
end

--- Registra uma chamada de remote
--- @param remote any Instância do remote
--- @param method string Método chamado (FireServer/InvokeServer)
--- @param args table Argumentos
function BehaviorAnalyzer:_recordRemoteCall(remote, method, args)
    local now = os.time()
    local remoteName = "unknown"
    pcall(function() remoteName = remote.Name end)

    local entry = {
        remote = remoteName,
        method = method,
        arg_count = #args,
        timestamp = now,
    }

    self.remoteCalls[#self.remoteCalls + 1] = entry
    self.stats.total_remote_calls = self.stats.total_remote_calls + 1
    self.stats.by_remote[remoteName] = (self.stats.by_remote[remoteName] or 0) + 1

    -- Detectar FireServer em loop (muitas chamadas por minuto)
    local callsLastMinute = 0
    for i = #self.remoteCalls, 1, -1 do
        local call = self.remoteCalls[i]
        if now - call.timestamp <= 60 then
            if call.remote == remoteName then
                callsLastMinute = callsLastMinute + 1
            end
        else
            break
        end
    end

    if callsLastMinute >= self.thresholds.max_fire_server_per_minute then
        self:_createAlert("FIRE_SERVER_LOOP", "HIGH", {
            remote = remoteName,
            calls_per_minute = callsLastMinute,
            threshold = self.thresholds.max_fire_server_per_minute,
            description = string.format(
                "'%s':%s chamado %d vezes/min - possível abuso de remote",
                remoteName, method, callsLastMinute
            ),
        })
    end
end

--- Registra criação de GUI
--- @param guiInstance any Instância GUI criada
function BehaviorAnalyzer:_recordGUICreation(guiInstance)
    local now = os.time()
    local entry = {
        name = "unknown",
        class = "unknown",
        visible = true,
        transparency = 0,
        timestamp = now,
    }

    pcall(function()
        entry.name = guiInstance.Name
        entry.class = guiInstance.ClassName
    end)

    -- Verificar se é invisível
    pcall(function()
        if guiInstance:IsA("ScreenGui") then
            entry.visible = guiInstance.Enabled ~= false
        end
        if guiInstance:IsA("GuiObject") then
            entry.visible = guiInstance.Visible ~= false
            entry.transparency = guiInstance.BackgroundTransparency or 0
        end
    end)

    self.guiCreations[#self.guiCreations + 1] = entry
    self.stats.total_gui_creations = self.stats.total_gui_creations + 1

    -- Detectar GUIs invisíveis
    if not entry.visible or entry.transparency >= 1 then
        local invisibleCount = 0
        for _, gui in ipairs(self.guiCreations) do
            if not gui.visible or gui.transparency >= 1 then
                invisibleCount = invisibleCount + 1
            end
        end

        if invisibleCount >= self.thresholds.max_invisible_guis then
            self:_createAlert("INVISIBLE_GUI_CREATION", "HIGH", {
                gui_name = entry.name,
                gui_class = entry.class,
                invisible_count = invisibleCount,
                threshold = self.thresholds.max_invisible_guis,
                description = string.format(
                    "GUI invisível criada: '%s' (%s) - %d GUIs invisíveis detectadas (possível backdoor)",
                    entry.name, entry.class, invisibleCount
                ),
            })
        end
    end
end

--- Cria um alerta de comportamento
--- @param alertType string Tipo do alerta
--- @param severity string Severidade
--- @param data table Dados do alerta
function BehaviorAnalyzer:_createAlert(alertType, severity, data)
    -- Evitar alertas duplicados no mesmo minuto
    local now = os.time()
    for _, alert in ipairs(self.alerts) do
        if alert.type == alertType and now - alert.timestamp < 60 then
            return -- Já alertado recentemente
        end
    end

    local alert = {
        type = alertType,
        severity = severity,
        data = data,
        timestamp = now,
        timestamp_iso = os.date("!%Y-%m-%dT%H:%M:%SZ", now),
    }

    self.alerts[#self.alerts + 1] = alert
    self.stats.total_alerts = self.stats.total_alerts + 1

    if self.logger then
        self.logger:warn("BEHAVIOR", string.format(
            "[%s] %s - %s", severity, alertType, data.description or ""
        ), alert)
    end
end

--- Analisa comportamento de um código de forma estática (sem hooks)
--- Identifica padrões que indicam comportamento malicioso em runtime
--- @param code string Código a analisar
--- @param source string Origem
--- @return table Lista de comportamentos suspeitos detectados
function BehaviorAnalyzer:analyzeCodeBehavior(code, source)
    if type(code) ~= "string" then return {} end

    local behaviors = {}

    -- Detectar loop + FireServer (abuso)
    if code:find("while%s+true%s+do") or code:find("for%s+.-%s+do") then
        if code:find("FireServer") or code:find("InvokeServer") then
            behaviors[#behaviors + 1] = {
                type = "LOOP_FIRE_SERVER",
                severity = "HIGH",
                description = "Loop com chamada FireServer/InvokeServer - possível abuso de remote",
                source = source,
            }
        end
    end

    -- Detectar criação em massa de instâncias
    local instanceNewCount = 0
    for _ in code:gmatch("Instance%.new") do
        instanceNewCount = instanceNewCount + 1
    end
    if instanceNewCount > 20 then
        behaviors[#behaviors + 1] = {
            type = "MASS_INSTANCE_CREATION",
            severity = "MEDIUM",
            count = instanceNewCount,
            description = string.format(
                "%d chamadas Instance.new - possível criação em massa", instanceNewCount
            ),
            source = source,
        }
    end

    -- Detectar criação de RemoteEvent via Instance.new
    if code:find('Instance%.new%s*%(%s*["\']RemoteEvent') then
        behaviors[#behaviors + 1] = {
            type = "DYNAMIC_REMOTE_CREATION",
            severity = "HIGH",
            description = "Criação dinâmica de RemoteEvent via script",
            source = source,
        }
    end

    -- Detectar criação de GUI invisível
    if code:find("ScreenGui") and (code:find("Enabled%s*=%s*false") or code:find("Visible%s*=%s*false")) then
        behaviors[#behaviors + 1] = {
            type = "INVISIBLE_GUI_PATTERN",
            severity = "HIGH",
            description = "Criação de GUI com visibilidade desabilitada - possível backdoor",
            source = source,
        }
    end

    -- Detectar spawn/task.spawn em loop
    if code:find("while%s+true") and (code:find("spawn") or code:find("task%.spawn") or code:find("task%.defer")) then
        behaviors[#behaviors + 1] = {
            type = "SPAWN_LOOP",
            severity = "MEDIUM",
            description = "Loop infinito com spawn de threads - possível DoS",
            source = source,
        }
    end

    -- Detectar wait(0) ou task.wait(0) em loop (high-frequency loop)
    if code:find("while%s+true") and (code:find("wait%s*%(0%)") or code:find("task%.wait%s*%(0%)")) then
        behaviors[#behaviors + 1] = {
            type = "HIGH_FREQUENCY_LOOP",
            severity = "MEDIUM",
            description = "Loop com wait(0) - execução de alta frequência, possível impacto de performance",
            source = source,
        }
    end

    return behaviors
end

--- Retorna todos os alertas
--- @return table
function BehaviorAnalyzer:getAlerts()
    return self.alerts
end

--- Retorna estatísticas
--- @return table
function BehaviorAnalyzer:getStats()
    return self.stats
end

--- Limpa dados coletados
function BehaviorAnalyzer:reset()
    self.instanceCreations = {}
    self.remoteCalls = {}
    self.guiCreations = {}
    self.alerts = {}
    self.stats = {
        total_instances_created = 0,
        total_remote_calls = 0,
        total_gui_creations = 0,
        total_alerts = 0,
        by_class = {},
        by_remote = {},
    }
end

return BehaviorAnalyzer
