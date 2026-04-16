--[[
    Scanning-Lua - Continuous Monitor Module (#24)
    Monitoramento contínuo em tempo real

    Não roda apenas uma vez:
    - Loop leve de verificação
    - Detecta scripts novos em tempo real
    - Monitora mudanças na árvore de instâncias
    - Rate-limited para não impactar performance
]]

local ContinuousMonitor = {}
ContinuousMonitor.__index = ContinuousMonitor

--- Cria uma nova instância do monitor contínuo
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table ContinuousMonitor instance
function ContinuousMonitor.new(config, logger)
    local self = setmetatable({}, ContinuousMonitor)
    self.config = config or {}
    self.logger = logger
    self.isRunning = false
    self.connections = {}
    self.knownScripts = {}
    self.newScriptCallbacks = {}
    self.scanInterval = config.SCAN_INTERVAL or 30
    self.stats = {
        total_cycles = 0,
        new_scripts_detected = 0,
        total_events = 0,
        start_time = nil,
    }
    return self
end

--- Inicia o monitoramento contínuo
--- @param scanCallback function Função chamada quando novo script é detectado
function ContinuousMonitor:start(scanCallback)
    if self.isRunning then
        if self.logger then
            self.logger:warn("CONTINUOUS", "Monitor já está rodando")
        end
        return
    end

    self.isRunning = true
    self.stats.start_time = os.time()

    if self.logger then
        self.logger:info("CONTINUOUS", string.format(
            "Monitor contínuo iniciado (intervalo: %ds)", self.scanInterval
        ))
    end

    -- Registrar callback
    if scanCallback then
        self.newScriptCallbacks[#self.newScriptCallbacks + 1] = scanCallback
    end

    -- Monitorar ChildAdded em serviços (Roblox)
    self:_installEventListeners()

    -- Iniciar loop de verificação
    self:_startMonitorLoop()
end

--- Para o monitoramento
function ContinuousMonitor:stop()
    self.isRunning = false

    -- Desconectar listeners
    for _, conn in ipairs(self.connections) do
        pcall(function()
            if conn and conn.Disconnect then
                conn:Disconnect()
            end
        end)
    end
    self.connections = {}

    if self.logger then
        self.logger:info("CONTINUOUS", "Monitor contínuo parado", self:getStats())
    end
end

--- Instala listeners de ChildAdded nos serviços principais
function ContinuousMonitor:_installEventListeners()
    local selfRef = self

    pcall(function()
        if not game or not game.GetService then return end

        local services = {
            "ReplicatedStorage", "Workspace", "StarterGui",
            "StarterPack", "Lighting", "ReplicatedFirst",
        }

        for _, serviceName in ipairs(services) do
            pcall(function()
                local service = game:GetService(serviceName)
                if not service then return end

                -- Listener recursivo para DescendantAdded
                local conn = service.DescendantAdded:Connect(function(descendant)
                    if not selfRef.isRunning then return end

                    local className = descendant.ClassName
                    if className == "Script" or className == "LocalScript" or className == "ModuleScript" then
                        selfRef:_onNewScript(descendant)
                    elseif className == "RemoteEvent" or className == "RemoteFunction" then
                        selfRef:_onNewRemote(descendant)
                    end
                end)

                selfRef.connections[#selfRef.connections + 1] = conn
            end)
        end

        if selfRef.logger then
            selfRef.logger:info("CONTINUOUS", string.format(
                "%d event listeners instalados", #selfRef.connections
            ))
        end
    end)
end

--- Callback quando um novo script é adicionado
--- @param scriptInstance any Instância do script
function ContinuousMonitor:_onNewScript(scriptInstance)
    local path = "unknown"
    pcall(function() path = scriptInstance:GetFullName() end)

    -- Verificar se já conhecemos este script
    if self.knownScripts[path] then return end

    self.knownScripts[path] = {
        name = scriptInstance.Name,
        class = scriptInstance.ClassName,
        detected_at = os.time(),
    }

    self.stats.new_scripts_detected = self.stats.new_scripts_detected + 1
    self.stats.total_events = self.stats.total_events + 1

    if self.logger then
        self.logger:info("CONTINUOUS", string.format(
            "Novo script detectado: %s (%s)", path, scriptInstance.ClassName
        ))
    end

    -- Notificar callbacks
    for _, cb in ipairs(self.newScriptCallbacks) do
        pcall(cb, scriptInstance, path)
    end
end

--- Callback quando um novo Remote é adicionado
--- @param remoteInstance any Instância do remote
function ContinuousMonitor:_onNewRemote(remoteInstance)
    self.stats.total_events = self.stats.total_events + 1

    local path = "unknown"
    pcall(function() path = remoteInstance:GetFullName() end)

    if self.logger then
        self.logger:info("CONTINUOUS", string.format(
            "Novo %s detectado: %s", remoteInstance.ClassName, path
        ))
    end
end

--- Loop principal de monitoramento (verificação periódica)
function ContinuousMonitor:_startMonitorLoop()
    local selfRef = self

    -- Usar task.spawn se disponível
    local hasTask = false
    pcall(function() hasTask = task and task.spawn ~= nil end)

    if hasTask then
        task.spawn(function()
            while selfRef.isRunning do
                selfRef:_runCycle()
                task.wait(selfRef.scanInterval)
            end
        end)
    else
        -- Fora do Roblox: executar um ciclo
        self:_runCycle()
    end
end

--- Executa um ciclo de verificação
function ContinuousMonitor:_runCycle()
    self.stats.total_cycles = self.stats.total_cycles + 1

    if self.logger then
        self.logger:debug("CONTINUOUS", string.format(
            "Ciclo #%d executado", self.stats.total_cycles
        ))
    end

    -- Verificar se scripts conhecidos ainda existem
    self:_checkKnownScripts()
end

--- Verifica se scripts conhecidos ainda existem (detecção de remoção)
function ContinuousMonitor:_checkKnownScripts()
    -- Em ambiente Roblox, verificar se instâncias ainda existem
    pcall(function()
        if not game then return end

        local toRemove = {}
        for path, info in pairs(self.knownScripts) do
            -- Se a info tem referência, verificar se ainda existe
            if info.instance then
                local success, hasParent = pcall(function()
                    return info.instance.Parent ~= nil
                end)
                if not success or not hasParent then
                    toRemove[#toRemove + 1] = path
                end
            end
        end

        for _, path in ipairs(toRemove) do
            self.knownScripts[path] = nil
            if self.logger then
                self.logger:info("CONTINUOUS", string.format(
                    "Script removido: %s", path
                ))
            end
        end
    end)
end

--- Registra um callback para quando novos scripts são detectados
--- @param callback function Função(scriptInstance, path)
function ContinuousMonitor:onNewScript(callback)
    self.newScriptCallbacks[#self.newScriptCallbacks + 1] = callback
end

--- Retorna scripts conhecidos
--- @return table
function ContinuousMonitor:getKnownScripts()
    return self.knownScripts
end

--- Retorna estatísticas
--- @return table
function ContinuousMonitor:getStats()
    local uptime = self.stats.start_time and (os.time() - self.stats.start_time) or 0
    return {
        is_running = self.isRunning,
        total_cycles = self.stats.total_cycles,
        new_scripts_detected = self.stats.new_scripts_detected,
        total_events = self.stats.total_events,
        uptime_seconds = uptime,
        known_scripts = self:_countKnownScripts(),
        connections = #self.connections,
    }
end

function ContinuousMonitor:_countKnownScripts()
    local count = 0
    for _ in pairs(self.knownScripts) do count = count + 1 end
    return count
end

--- Limpa dados
function ContinuousMonitor:reset()
    self:stop()
    self.knownScripts = {}
    self.newScriptCallbacks = {}
    self.stats = {
        total_cycles = 0,
        new_scripts_detected = 0,
        total_events = 0,
        start_time = nil,
    }
end

return ContinuousMonitor
