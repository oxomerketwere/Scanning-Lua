--[[
    Scanning-Lua - Scanner Core Module
    Motor principal de scan para análise de instâncias e scripts Roblox
    Escaneia a árvore de objetos e coleta informações de segurança
]]

local JSON = require("modules.json")

local Scanner = {}
Scanner.__index = Scanner

--- Cria uma nova instância do Scanner
--- @param config table Configurações do scanner (de Config.Scanner)
--- @param logger table Instância do Logger
--- @param filters table Instância do módulo Filters
--- @return table Scanner instance
function Scanner.new(config, logger, filters)
    local self = setmetatable({}, Scanner)
    self.config = config or {}
    self.logger = logger
    self.filters = filters
    self.results = {
        remote_events = {},
        remote_functions = {},
        bindable_events = {},
        scripts = {},
        http_requests = {},
        datastore_access = {},
        suspicious_items = {},
        vulnerabilities = {},
    }
    self.scanCount = 0
    self.isScanning = false
    self.connections = {} -- Rastrear conexões de monitoramento para cleanup
    self.hooks = {}       -- Rastrear hooks instalados para cleanup
    return self
end

--- Escaneia a árvore de descendentes de uma instância (compatível com Roblox)
--- Quando executado fora do Roblox, aceita tabelas simulando a estrutura
--- @param instance table Instância raiz para scan
--- @param depth number Profundidade atual
function Scanner:scanInstance(instance, depth)
    depth = depth or 0

    if depth > (self.config.MAX_DEPTH or 50) then
        if self.logger then
            self.logger:warn("SCANNER", "Profundidade máxima atingida", {
                depth = depth,
                instance_name = instance.Name or "unknown",
            })
        end
        return
    end

    if not instance then return end

    local name = instance.Name or "unnamed"
    local className = instance.ClassName or "unknown"
    local fullPath = instance.GetFullName and instance:GetFullName() or name

    -- Escanear RemoteEvents
    if className == "RemoteEvent" and self.config.SCAN_REMOTE_EVENTS then
        self:_registerRemoteEvent(instance, fullPath)
    end

    -- Escanear RemoteFunctions
    if className == "RemoteFunction" and self.config.SCAN_REMOTE_FUNCTIONS then
        self:_registerRemoteFunction(instance, fullPath)
    end

    -- Escanear BindableEvents
    if className == "BindableEvent" and self.config.SCAN_BINDABLE_EVENTS then
        self:_registerBindableEvent(instance, fullPath)
    end

    -- Escanear Scripts (LocalScript, Script, ModuleScript)
    if className == "LocalScript" or className == "Script" or className == "ModuleScript" then
        self:_scanScript(instance, fullPath, className)
    end

    -- Escanear filhos recursivamente
    local children = instance.GetChildren and instance:GetChildren() or instance.children or {}
    for _, child in ipairs(children) do
        self:scanInstance(child, depth + 1)
    end
end

--- Registra um RemoteEvent encontrado
--- @param instance table Instância do RemoteEvent
--- @param path string Caminho completo
function Scanner:_registerRemoteEvent(instance, path)
    local entry = {
        name = instance.Name,
        path = path,
        class = "RemoteEvent",
        scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        parent = instance.Parent and instance.Parent.Name or "nil",
    }

    self.results.remote_events[#self.results.remote_events + 1] = entry

    -- Verificar nome suspeito via filtros
    if self.filters then
        local nameMatch = self.filters:analyzeRemoteName(instance.Name, path)
        if nameMatch then
            entry.suspicious = true
            entry.filter_match = nameMatch
            self.results.suspicious_items[#self.results.suspicious_items + 1] = {
                type = "SUSPICIOUS_REMOTE_EVENT",
                details = entry,
            }
        end
    end

    if self.logger then
        self.logger:info("SCANNER", string.format("RemoteEvent encontrado: %s", path), entry)
    end
end

--- Registra uma RemoteFunction encontrada
--- @param instance table Instância da RemoteFunction
--- @param path string Caminho completo
function Scanner:_registerRemoteFunction(instance, path)
    local entry = {
        name = instance.Name,
        path = path,
        class = "RemoteFunction",
        scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        parent = instance.Parent and instance.Parent.Name or "nil",
    }

    self.results.remote_functions[#self.results.remote_functions + 1] = entry

    if self.filters then
        local nameMatch = self.filters:analyzeRemoteName(instance.Name, path)
        if nameMatch then
            entry.suspicious = true
            entry.filter_match = nameMatch
            self.results.suspicious_items[#self.results.suspicious_items + 1] = {
                type = "SUSPICIOUS_REMOTE_FUNCTION",
                details = entry,
            }
        end
    end

    if self.logger then
        self.logger:info("SCANNER", string.format("RemoteFunction encontrada: %s", path), entry)
    end
end

--- Registra um BindableEvent encontrado
--- @param instance table Instância do BindableEvent
--- @param path string Caminho completo
function Scanner:_registerBindableEvent(instance, path)
    local entry = {
        name = instance.Name,
        path = path,
        class = "BindableEvent",
        scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    }

    self.results.bindable_events[#self.results.bindable_events + 1] = entry

    if self.logger then
        self.logger:debug("SCANNER", string.format("BindableEvent encontrado: %s", path), entry)
    end
end

--- Escaneia o código-fonte de um script
--- @param instance table Instância do script
--- @param path string Caminho completo
--- @param scriptType string Tipo do script
function Scanner:_scanScript(instance, path, scriptType)
    -- Tenta obter o código-fonte (depende do executor/ambiente)
    local source = nil

    -- Tentativa 1: Propriedade Source direta
    local success = pcall(function()
        source = instance.Source
    end)

    -- Tentativa 2: Usando decompile (disponível em alguns executors)
    if not success or not source then
        local decompileSuccess = pcall(function()
            if decompile then
                source = decompile(instance)
            end
        end)
        if not decompileSuccess then
            source = nil
        end
    end

    local entry = {
        name = instance.Name,
        path = path,
        class = scriptType,
        has_source = source ~= nil,
        source_length = source and #source or 0,
        scan_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        enabled = instance.Enabled ~= false,
    }

    -- Analisar código com filtros
    if source and self.filters then
        local matches = self.filters:analyzeCode(source, path)
        if #matches > 0 then
            entry.suspicious = true
            entry.filter_matches = matches
            entry.match_count = #matches

            for _, match in ipairs(matches) do
                self.results.suspicious_items[#self.results.suspicious_items + 1] = {
                    type = "SUSPICIOUS_CODE",
                    script_path = path,
                    details = match,
                }
            end

            if self.logger then
                self.logger:warn("SCANNER", string.format(
                    "Script com %d padrões suspeitos: %s",
                    #matches, path
                ), { path = path, matches = #matches })
            end
        end
    end

    self.results.scripts[#self.results.scripts + 1] = entry

    if self.logger then
        self.logger:debug("SCANNER", string.format(
            "Script analisado: %s [%s] (source: %s)",
            path, scriptType, tostring(source ~= nil)
        ))
    end
end

--- Escaneia serviços do Roblox (quando executado no ambiente Roblox)
--- @param game table Objeto game do Roblox (ou mock)
function Scanner:scanServices(game)
    if not game then
        if self.logger then
            self.logger:error("SCANNER", "Objeto 'game' não disponível")
        end
        return
    end

    self.isScanning = true
    self.scanCount = self.scanCount + 1

    if self.logger then
        self.logger:info("SCANNER", string.format("Iniciando scan #%d dos serviços", self.scanCount))
    end

    local services = {
        "ReplicatedStorage",
        "ReplicatedFirst",
        "ServerScriptService",
        "ServerStorage",
        "Workspace",
        "Players",
        "Lighting",
        "StarterGui",
        "StarterPack",
        "StarterPlayer",
        "Chat",
        "SoundService",
        "Teams",
    }

    for _, serviceName in ipairs(services) do
        local success, service = pcall(function()
            if game.GetService then
                return game:GetService(serviceName)
            end
            return game[serviceName]
        end)

        if success and service then
            if self.logger then
                self.logger:debug("SCANNER", string.format("Escaneando serviço: %s", serviceName))
            end
            self:scanInstance(service, 0)
        else
            if self.logger then
                self.logger:debug("SCANNER", string.format(
                    "Serviço não acessível: %s", serviceName
                ))
            end
        end
    end

    self.isScanning = false

    if self.logger then
        self.logger:info("SCANNER", "Scan de serviços concluído", self:getSummary())
    end
end

--- Escaneia apenas serviços específicos
--- @param game table Objeto game do Roblox
--- @param serviceList table Lista de nomes de serviços para escanear
function Scanner:scanSelectiveServices(game, serviceList)
    if not game or not serviceList then return end

    self.isScanning = true
    self.scanCount = self.scanCount + 1

    if self.logger then
        self.logger:info("SCANNER", string.format(
            "Scan seletivo #%d: %d serviços", self.scanCount, #serviceList
        ))
    end

    for _, serviceName in ipairs(serviceList) do
        local success, service = pcall(function()
            return game:GetService(serviceName)
        end)
        if success and service then
            self:scanInstance(service, 0)
        end
    end

    self.isScanning = false

    if self.logger then
        self.logger:info("SCANNER", "Scan seletivo concluído", self:getSummary())
    end
end

--- Escaneia instâncias de forma assíncrona usando task.defer (quando disponível)
--- @param instance table Instância raiz
--- @param callback function|nil Callback quando concluído
function Scanner:scanInstanceAsync(instance, callback)
    local taskAvailable = pcall(function() return task and task.defer end)

    if not taskAvailable then
        -- Fallback para scan síncrono
        self:scanInstance(instance, 0)
        if callback then callback(self:getSummary()) end
        return
    end

    self.isScanning = true

    task.defer(function()
        self:scanInstance(instance, 0)
        self.isScanning = false
        if callback then callback(self:getSummary()) end
    end)
end

--- Desconecta todas as conexões de monitoramento
function Scanner:disconnectAll()
    for _, conn in ipairs(self.connections) do
        pcall(function()
            if conn and conn.Disconnect then
                conn:Disconnect()
            end
        end)
    end
    self.connections = {}

    if self.logger then
        self.logger:info("SCANNER", "Todas as conexões desconectadas")
    end
end

--- Monitora um RemoteEvent para interceptar chamadas
--- @param remote table Instância do RemoteEvent
--- @param callback function Função callback chamada a cada intercepção
--- @return table|nil Conexão do evento (para desconectar depois)
function Scanner:monitorRemote(remote, callback)
    if not remote then return nil end

    local connection
    local success = pcall(function()
        -- Tenta conectar ao OnClientEvent (client-side)
        if remote.OnClientEvent then
            connection = remote.OnClientEvent:Connect(function(...)
                local args = { ... }
                local entry = {
                    remote_name = remote.Name,
                    remote_path = remote:GetFullName(),
                    args = args,
                    arg_count = #args,
                    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                }

                -- Analisar argumentos via filtros
                if self.filters then
                    local alerts = self.filters:analyzeRemoteArgs(args, remote.Name)
                    if #alerts > 0 then
                        entry.alerts = alerts
                    end
                end

                if self.logger then
                    self.logger:info("MONITOR", string.format(
                        "Remote interceptado: %s (%d args)",
                        remote.Name, #args
                    ), entry)
                end

                if callback then
                    callback(entry)
                end
            end)
        end
    end)

    if not success then
        if self.logger then
            self.logger:error("SCANNER", string.format(
                "Falha ao monitorar remote: %s", remote.Name or "unknown"
            ))
        end
    end

    return connection
end

--- Escaneia chamadas HTTP (quando disponível no executor)
function Scanner:scanHTTPActivity()
    if not self.config.SCAN_HTTP_REQUESTS then return end

    -- Tenta interceptar via hookfunction (disponível em executors avançados)
    local success = pcall(function()
        if hookfunction and game and game.HttpGet then
            local originalHttpGet = hookfunction(game.HttpGet, function(self_ref, url, ...)
                local entry = {
                    type = "HTTP_GET",
                    url = url,
                    timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                }
                if self.logger then
                    self.logger:warn("HTTP", string.format("HTTP GET interceptado: %s", url), entry)
                end
                self.results.http_requests[#self.results.http_requests + 1] = entry
                return originalHttpGet(self_ref, url, ...)
            end)
        end
    end)

    if not success and self.logger then
        self.logger:debug("SCANNER", "HTTP hooking não disponível neste ambiente")
    end
end

--- Retorna um resumo dos resultados do scan
--- @return table Resumo com contadores
function Scanner:getSummary()
    return {
        scan_count = self.scanCount,
        remote_events = #self.results.remote_events,
        remote_functions = #self.results.remote_functions,
        bindable_events = #self.results.bindable_events,
        scripts_analyzed = #self.results.scripts,
        http_requests_logged = #self.results.http_requests,
        suspicious_items = #self.results.suspicious_items,
        vulnerabilities = #self.results.vulnerabilities,
    }
end

--- Exporta os resultados completos em formato JSON
--- @return string JSON com todos os resultados
function Scanner:exportResults()
    local report = {
        scanner_version = "1.0.0",
        scan_count = self.scanCount,
        export_time = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        summary = self:getSummary(),
        results = self.results,
    }
    return JSON.encodePretty(report)
end

--- Salva os resultados em um arquivo JSON
--- @param filepath string Caminho do arquivo
--- @return boolean success
--- @return string|nil error
function Scanner:saveResults(filepath)
    local jsonStr = self:exportResults()
    local file, err = io.open(filepath, "w")
    if not file then
        if self.logger then
            self.logger:error("SCANNER", "Falha ao salvar resultados: " .. tostring(err))
        end
        return false, err
    end
    file:write(jsonStr)
    file:close()

    if self.logger then
        self.logger:info("SCANNER", string.format("Resultados salvos em: %s", filepath))
    end
    return true
end

--- Retorna os resultados completos
--- @return table
function Scanner:getResults()
    return self.results
end

--- Limpa todos os resultados
function Scanner:reset()
    self.results = {
        remote_events = {},
        remote_functions = {},
        bindable_events = {},
        scripts = {},
        http_requests = {},
        datastore_access = {},
        suspicious_items = {},
        vulnerabilities = {},
    }
    self.scanCount = 0
end

return Scanner
