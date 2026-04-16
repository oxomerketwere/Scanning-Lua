--[[
    Scanning-Lua - Script Correlator Module (#23)
    Correlação entre scripts para detectar ecossistemas maliciosos

    Detecta:
    - Scripts que se comunicam entre si
    - Um script baixa payload, outro executa
    - Cadeias de ataque multi-script
    - Padrões de coordenação entre scripts maliciosos
]]

local ScriptCorrelator = {}
ScriptCorrelator.__index = ScriptCorrelator

--- Cria uma nova instância do correlator
--- @param logger table Instância do Logger
--- @return table ScriptCorrelator instance
function ScriptCorrelator.new(logger)
    local self = setmetatable({}, ScriptCorrelator)
    self.logger = logger
    self.scriptProfiles = {}       -- Perfil de cada script analisado
    self.correlations = {}          -- Correlações encontradas
    self.sharedResources = {}       -- Recursos compartilhados entre scripts
    self.stats = {
        total_scripts_profiled = 0,
        total_correlations = 0,
        ecosystems_detected = 0,
    }
    return self
end

--- Cria perfil de um script para correlação
--- @param code string Código do script
--- @param source string Identificador do script
--- @return table Perfil do script
function ScriptCorrelator:profileScript(code, source)
    if type(code) ~= "string" then return {} end

    local profile = {
        source = source,
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        uses_remotes = {},
        creates_remotes = {},
        http_urls = {},
        require_ids = {},
        global_writes = {},
        global_reads = {},
        shared_variables = {},
        capabilities = {},
    }

    -- Detectar uso de RemoteEvents
    for remoteName in code:gmatch('["\']([%w_]+)["\']%s*:%s*FireServer') do
        profile.uses_remotes[#profile.uses_remotes + 1] = remoteName
    end
    for remoteName in code:gmatch('FindFirstChild%s*%(%s*["\']([%w_]+)["\']%)') do
        profile.uses_remotes[#profile.uses_remotes + 1] = remoteName
    end

    -- Detectar criação de RemoteEvents
    for _ in code:gmatch('Instance%.new%s*%(%s*["\']RemoteEvent') do
        profile.creates_remotes[#profile.creates_remotes + 1] = source
    end
    for _ in code:gmatch('Instance%.new%s*%(%s*["\']RemoteFunction') do
        profile.creates_remotes[#profile.creates_remotes + 1] = source
    end

    -- Detectar URLs HTTP
    for url in code:gmatch('["\']https?://([^"\']+)["\']') do
        profile.http_urls[#profile.http_urls + 1] = url
    end

    -- Detectar require IDs
    for id in code:gmatch('require%s*%((%d+)%)') do
        profile.require_ids[#profile.require_ids + 1] = id
    end

    -- Detectar escrita em globais
    for varName in code:gmatch('getgenv%(%)["\']([%w_]+)["\']%s*=') do
        profile.global_writes[#profile.global_writes + 1] = varName
    end
    for varName in code:gmatch('_G%s*%.%s*([%w_]+)%s*=') do
        profile.global_writes[#profile.global_writes + 1] = varName
    end
    for varName in code:gmatch('shared%s*%.%s*([%w_]+)%s*=') do
        profile.global_writes[#profile.global_writes + 1] = varName
    end

    -- Detectar leitura de globais
    for varName in code:gmatch('getgenv%(%)["\']([%w_]+)["\']%s*[^=]') do
        profile.global_reads[#profile.global_reads + 1] = varName
    end
    for varName in code:gmatch('_G%s*%.%s*([%w_]+)%s*[^=]') do
        profile.global_reads[#profile.global_reads + 1] = varName
    end
    for varName in code:gmatch('shared%s*%.%s*([%w_]+)%s*[^=]') do
        profile.global_reads[#profile.global_reads + 1] = varName
    end

    -- Classificar capacidades
    if code:find("HttpGet") or code:find("HttpPost") or code:find("syn%.request") then
        profile.capabilities[#profile.capabilities + 1] = "NETWORK"
    end
    if code:find("loadstring") then
        profile.capabilities[#profile.capabilities + 1] = "CODE_EXECUTION"
    end
    if code:find("hookfunction") or code:find("hookmetamethod") then
        profile.capabilities[#profile.capabilities + 1] = "HOOKING"
    end
    if code:find("getrawmetatable") then
        profile.capabilities[#profile.capabilities + 1] = "METATABLE_ACCESS"
    end
    if code:find("FireServer") or code:find("InvokeServer") then
        profile.capabilities[#profile.capabilities + 1] = "REMOTE_CALL"
    end
    if code:find("writefile") or code:find("readfile") then
        profile.capabilities[#profile.capabilities + 1] = "FILESYSTEM"
    end

    -- Armazenar perfil
    self.scriptProfiles[source] = profile
    self.stats.total_scripts_profiled = self.stats.total_scripts_profiled + 1

    return profile
end

--- Analisa correlações entre todos os scripts perfilados
--- @return table Lista de correlações encontradas
function ScriptCorrelator:analyzeCorrelations()
    local correlations = {}
    local sources = {}
    for source in pairs(self.scriptProfiles) do
        sources[#sources + 1] = source
    end

    -- Comparar cada par de scripts
    for i = 1, #sources do
        for j = i + 1, #sources do
            local profileA = self.scriptProfiles[sources[i]]
            local profileB = self.scriptProfiles[sources[j]]
            local found = self:_correlateProfiles(profileA, profileB)

            for _, corr in ipairs(found) do
                correlations[#correlations + 1] = corr
            end
        end
    end

    self.correlations = correlations
    self.stats.total_correlations = #correlations

    -- Detectar ecossistemas
    local ecosystems = self:_detectEcosystems(correlations)
    self.stats.ecosystems_detected = #ecosystems

    if self.logger and #correlations > 0 then
        self.logger:warn("CORRELATOR", string.format(
            "%d correlações encontradas entre %d scripts, %d ecossistemas detectados",
            #correlations, #sources, #ecosystems
        ))
    end

    return correlations
end

--- Correlaciona dois perfis de scripts
--- @param profileA table Perfil do script A
--- @param profileB table Perfil do script B
--- @return table Lista de correlações
function ScriptCorrelator:_correlateProfiles(profileA, profileB)
    local correlations = {}

    -- 1. Compartilhamento de variáveis globais
    -- Script A escreve e Script B lê (ou vice-versa)
    for _, writeVar in ipairs(profileA.global_writes) do
        for _, readVar in ipairs(profileB.global_reads) do
            if writeVar == readVar then
                correlations[#correlations + 1] = {
                    type = "SHARED_GLOBAL_VARIABLE",
                    severity = "HIGH",
                    script_a = profileA.source,
                    script_b = profileB.source,
                    variable = writeVar,
                    description = string.format(
                        "'%s' escreve variável '%s' que '%s' lê - comunicação entre scripts",
                        profileA.source, writeVar, profileB.source
                    ),
                }
            end
        end
    end

    for _, writeVar in ipairs(profileB.global_writes) do
        for _, readVar in ipairs(profileA.global_reads) do
            if writeVar == readVar then
                correlations[#correlations + 1] = {
                    type = "SHARED_GLOBAL_VARIABLE",
                    severity = "HIGH",
                    script_a = profileB.source,
                    script_b = profileA.source,
                    variable = writeVar,
                    description = string.format(
                        "'%s' escreve variável '%s' que '%s' lê - comunicação entre scripts",
                        profileB.source, writeVar, profileA.source
                    ),
                }
            end
        end
    end

    -- 2. Mesmo URL HTTP (payload compartilhado)
    for _, urlA in ipairs(profileA.http_urls) do
        for _, urlB in ipairs(profileB.http_urls) do
            if urlA == urlB then
                correlations[#correlations + 1] = {
                    type = "SHARED_HTTP_URL",
                    severity = "HIGH",
                    script_a = profileA.source,
                    script_b = profileB.source,
                    url = urlA,
                    description = string.format(
                        "Scripts '%s' e '%s' acessam mesmo URL: %s",
                        profileA.source, profileB.source, urlA
                    ),
                }
            end
        end
    end

    -- 3. Mesmo require ID
    for _, idA in ipairs(profileA.require_ids) do
        for _, idB in ipairs(profileB.require_ids) do
            if idA == idB then
                correlations[#correlations + 1] = {
                    type = "SHARED_REQUIRE_ID",
                    severity = "MEDIUM",
                    script_a = profileA.source,
                    script_b = profileB.source,
                    require_id = idA,
                    description = string.format(
                        "Scripts compartilham mesmo require ID: %s", idA
                    ),
                }
            end
        end
    end

    -- 4. Cadeia downloader → executor
    local aHasNetwork = self:_hasCapability(profileA, "NETWORK")
    local bHasExecution = self:_hasCapability(profileB, "CODE_EXECUTION")
    local bHasNetwork = self:_hasCapability(profileB, "NETWORK")
    local aHasExecution = self:_hasCapability(profileA, "CODE_EXECUTION")

    if aHasNetwork and bHasExecution and not aHasExecution then
        correlations[#correlations + 1] = {
            type = "DOWNLOADER_EXECUTOR_CHAIN",
            severity = "CRITICAL",
            script_a = profileA.source,
            script_b = profileB.source,
            description = string.format(
                "Possível cadeia: '%s' (downloader) + '%s' (executor)",
                profileA.source, profileB.source
            ),
        }
    end
    if bHasNetwork and aHasExecution and not bHasExecution then
        correlations[#correlations + 1] = {
            type = "DOWNLOADER_EXECUTOR_CHAIN",
            severity = "CRITICAL",
            script_a = profileB.source,
            script_b = profileA.source,
            description = string.format(
                "Possível cadeia: '%s' (downloader) + '%s' (executor)",
                profileB.source, profileA.source
            ),
        }
    end

    -- 5. Uso dos mesmos remotes
    for _, remA in ipairs(profileA.uses_remotes) do
        for _, remB in ipairs(profileB.uses_remotes) do
            if remA == remB then
                correlations[#correlations + 1] = {
                    type = "SHARED_REMOTE_USAGE",
                    severity = "MEDIUM",
                    script_a = profileA.source,
                    script_b = profileB.source,
                    remote = remA,
                    description = string.format(
                        "Scripts compartilham uso do remote '%s'", remA
                    ),
                }
            end
        end
    end

    return correlations
end

--- Verifica se um perfil tem uma capacidade
function ScriptCorrelator:_hasCapability(profile, cap)
    for _, c in ipairs(profile.capabilities) do
        if c == cap then return true end
    end
    return false
end

--- Detecta ecossistemas (grupos de scripts correlacionados)
--- @param correlations table
--- @return table Lista de ecossistemas
function ScriptCorrelator:_detectEcosystems(correlations)
    local graph = {} -- { source → { connected sources } }

    for _, corr in ipairs(correlations) do
        if not graph[corr.script_a] then graph[corr.script_a] = {} end
        if not graph[corr.script_b] then graph[corr.script_b] = {} end
        graph[corr.script_a][corr.script_b] = true
        graph[corr.script_b][corr.script_a] = true
    end

    -- BFS para encontrar componentes conectados
    local visited = {}
    local ecosystems = {}

    for source in pairs(graph) do
        if not visited[source] then
            local ecosystem = {}
            local queue = { source }

            while #queue > 0 do
                local current = table.remove(queue, 1)
                if not visited[current] then
                    visited[current] = true
                    ecosystem[#ecosystem + 1] = current

                    for neighbor in pairs(graph[current] or {}) do
                        if not visited[neighbor] then
                            queue[#queue + 1] = neighbor
                        end
                    end
                end
            end

            if #ecosystem > 1 then
                ecosystems[#ecosystems + 1] = {
                    scripts = ecosystem,
                    size = #ecosystem,
                    severity = "HIGH",
                    description = string.format(
                        "Ecossistema de %d scripts correlacionados detectado", #ecosystem
                    ),
                }
            end
        end
    end

    return ecosystems
end

--- Retorna correlações
--- @return table
function ScriptCorrelator:getCorrelations()
    return self.correlations
end

--- Retorna perfis de scripts
--- @return table
function ScriptCorrelator:getProfiles()
    return self.scriptProfiles
end

--- Retorna estatísticas
--- @return table
function ScriptCorrelator:getStats()
    return self.stats
end

--- Limpa dados
function ScriptCorrelator:reset()
    self.scriptProfiles = {}
    self.correlations = {}
    self.sharedResources = {}
    self.stats = {
        total_scripts_profiled = 0,
        total_correlations = 0,
        ecosystems_detected = 0,
    }
end

return ScriptCorrelator
