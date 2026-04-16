--[[
    Scanning-Lua - Hook Detector Module (#17)
    Detecção de hooks maliciosos instalados por outros scripts

    Outros scripts podem:
    - Hookar funções críticas
    - Interceptar dados
    - Alterar metatables

    Detecta:
    - hookfunction instalados
    - getrawmetatable alterados
    - Funções nativas que foram substituídas
    - __namecall/__index hooks
]]

local HookDetector = {}
HookDetector.__index = HookDetector

--- Cria uma nova instância do detector de hooks
--- @param logger table Instância do Logger
--- @return table HookDetector instance
function HookDetector.new(logger)
    local self = setmetatable({}, HookDetector)
    self.logger = logger
    self.baselineSnapshots = {}    -- Snapshot das funções originais
    self.detectedHooks = {}
    self.monitoredFunctions = {}
    self.stats = {
        total_checks = 0,
        hooks_detected = 0,
        functions_monitored = 0,
    }
    return self
end

--- Captura snapshot das funções originais (baseline)
--- Deve ser executado o mais cedo possível
function HookDetector:captureBaseline()
    if self.logger then
        self.logger:info("HOOK_DETECT", "Capturando baseline de funções originais")
    end

    local functions = {
        -- Funções globais críticas
        { name = "print", ref = print },
        { name = "warn", ref = warn },
        { name = "error", ref = error },
        { name = "type", ref = type },
        { name = "tostring", ref = tostring },
        { name = "tonumber", ref = tonumber },
        { name = "pcall", ref = pcall },
        { name = "require", ref = require },
        { name = "rawget", ref = rawget },
        { name = "rawset", ref = rawset },
        { name = "setmetatable", ref = setmetatable },
        { name = "getmetatable", ref = getmetatable },
    }

    -- Verificar funções de módulos
    if os then
        functions[#functions + 1] = { name = "os.time", ref = os.time }
        functions[#functions + 1] = { name = "os.date", ref = os.date }
        functions[#functions + 1] = { name = "os.clock", ref = os.clock }
    end

    if string then
        functions[#functions + 1] = { name = "string.find", ref = string.find }
        functions[#functions + 1] = { name = "string.match", ref = string.match }
        functions[#functions + 1] = { name = "string.gsub", ref = string.gsub }
    end

    if table then
        functions[#functions + 1] = { name = "table.insert", ref = table.insert }
        functions[#functions + 1] = { name = "table.remove", ref = table.remove }
        functions[#functions + 1] = { name = "table.concat", ref = table.concat }
    end

    for _, fn in ipairs(functions) do
        if fn.ref then
            self.baselineSnapshots[fn.name] = {
                reference = fn.ref,
                type = type(fn.ref),
                is_c_closure = nil,
                captured_at = os.time(),
            }

            -- Verificar se é cclosure (se disponível)
            pcall(function()
                if iscclosure then
                    self.baselineSnapshots[fn.name].is_c_closure = iscclosure(fn.ref)
                end
            end)

            self.stats.functions_monitored = self.stats.functions_monitored + 1
        end
    end

    -- Capturar metatables importantes
    pcall(function()
        if game and getrawmetatable then
            local mt = getrawmetatable(game)
            if mt then
                self.baselineSnapshots["__game_metatable"] = {
                    namecall = mt.__namecall,
                    index = mt.__index,
                    newindex = mt.__newindex,
                    captured_at = os.time(),
                }
            end
        end
    end)

    if self.logger then
        self.logger:info("HOOK_DETECT", string.format(
            "Baseline capturada: %d funções monitoradas", self.stats.functions_monitored
        ))
    end
end

--- Verifica se alguma função foi hookada desde o baseline
--- @return table Lista de hooks detectados
function HookDetector:checkForHooks()
    self.stats.total_checks = self.stats.total_checks + 1
    local newHooks = {}

    for name, baseline in pairs(self.baselineSnapshots) do
        if name == "__game_metatable" then
            -- Verificar metatable do game
            self:_checkMetatableHooks(baseline, newHooks)
        else
            -- Verificar função individual
            self:_checkFunctionHook(name, baseline, newHooks)
        end
    end

    -- Verificar funções de hooking que não deveriam existir
    self:_checkSuspiciousGlobals(newHooks)

    -- Registrar novos hooks
    for _, hook in ipairs(newHooks) do
        -- Evitar duplicatas
        local isDuplicate = false
        for _, existing in ipairs(self.detectedHooks) do
            if existing.function_name == hook.function_name and existing.type == hook.type then
                isDuplicate = true
                break
            end
        end

        if not isDuplicate then
            self.detectedHooks[#self.detectedHooks + 1] = hook
            self.stats.hooks_detected = self.stats.hooks_detected + 1

            if self.logger then
                self.logger:warn("HOOK_DETECT", string.format(
                    "Hook detectado: %s (%s) - %s",
                    hook.function_name, hook.type, hook.severity
                ), hook)
            end
        end
    end

    return newHooks
end

--- Verifica se uma função individual foi hookada
--- @param name string Nome da função
--- @param baseline table Baseline capturada
--- @param hooks table Lista para adicionar hooks detectados
function HookDetector:_checkFunctionHook(name, baseline, hooks)
    -- Obter referência atual da função
    local currentRef = nil
    pcall(function()
        if name:find("%.") then
            local parts = {}
            for part in name:gmatch("[^.]+") do
                parts[#parts + 1] = part
            end
            if #parts == 2 then
                currentRef = _G[parts[1]] and _G[parts[1]][parts[2]]
            end
        else
            currentRef = _G[name]
        end
    end)

    if not currentRef then
        -- Função foi removida
        hooks[#hooks + 1] = {
            function_name = name,
            type = "FUNCTION_REMOVED",
            severity = "HIGH",
            description = string.format("Função '%s' foi removida do ambiente global", name),
            detected_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
        return
    end

    -- Verificar se a referência mudou
    if currentRef ~= baseline.reference then
        hooks[#hooks + 1] = {
            function_name = name,
            type = "REFERENCE_CHANGED",
            severity = "CRITICAL",
            description = string.format("Referência de '%s' foi alterada (possível hook)", name),
            detected_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
    end

    -- Verificar se mudou de cclosure para lclosure (indica hook)
    if baseline.is_c_closure ~= nil then
        pcall(function()
            if iscclosure then
                local currentIsCClosure = iscclosure(currentRef)
                if baseline.is_c_closure and not currentIsCClosure then
                    hooks[#hooks + 1] = {
                        function_name = name,
                        type = "CLOSURE_TYPE_CHANGED",
                        severity = "CRITICAL",
                        description = string.format(
                            "'%s' mudou de cclosure para lclosure - forte indicação de hook", name
                        ),
                        detected_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
                    }
                end
            end
        end)
    end
end

--- Verifica hooks na metatable do game
--- @param baseline table Baseline da metatable
--- @param hooks table Lista para adicionar hooks detectados
function HookDetector:_checkMetatableHooks(baseline, hooks)
    pcall(function()
        if not game or not getrawmetatable then return end

        local mt = getrawmetatable(game)
        if not mt then return end

        if mt.__namecall ~= baseline.namecall then
            hooks[#hooks + 1] = {
                function_name = "__namecall",
                type = "METATABLE_HOOK",
                severity = "CRITICAL",
                description = "game.__namecall foi hookado - chamadas de método podem ser interceptadas",
                detected_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            }
        end

        if mt.__index ~= baseline.index then
            hooks[#hooks + 1] = {
                function_name = "__index",
                type = "METATABLE_HOOK",
                severity = "CRITICAL",
                description = "game.__index foi hookado - leituras de propriedade podem ser interceptadas",
                detected_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            }
        end

        if mt.__newindex ~= baseline.newindex then
            hooks[#hooks + 1] = {
                function_name = "__newindex",
                type = "METATABLE_HOOK",
                severity = "HIGH",
                description = "game.__newindex foi hookado - escritas podem ser interceptadas",
                detected_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            }
        end
    end)
end

--- Verifica presença de globais suspeitas que indicam hooking
--- @param hooks table Lista para adicionar hooks detectados
function HookDetector:_checkSuspiciousGlobals(hooks)
    -- Se essas funções existem no global, alguém carregou ferramentas de exploit
    local suspiciousGlobals = {
        { name = "hookfunction", severity = "HIGH", desc = "Função de hooking disponível no ambiente" },
        { name = "hookmetamethod", severity = "HIGH", desc = "Função de hook de metatable disponível" },
        { name = "replaceclosure", severity = "HIGH", desc = "Função de substituição de closure disponível" },
    }

    for _, sg in ipairs(suspiciousGlobals) do
        local exists = false
        pcall(function()
            exists = type(_G[sg.name]) == "function"
        end)

        if exists then
            hooks[#hooks + 1] = {
                function_name = sg.name,
                type = "SUSPICIOUS_GLOBAL",
                severity = sg.severity,
                description = sg.desc,
                detected_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            }
        end
    end
end

--- Analisa código em busca de padrões de hooking
--- @param code string Código a analisar
--- @param source string Origem
--- @return table Lista de padrões de hook encontrados
function HookDetector:analyzeCode(code, source)
    if type(code) ~= "string" then return {} end

    local patterns = {}

    local hookPatterns = {
        { pattern = "hookfunction", name = "hookfunction", severity = "CRITICAL" },
        { pattern = "hookmetamethod", name = "hookmetamethod", severity = "CRITICAL" },
        { pattern = "getrawmetatable", name = "getrawmetatable", severity = "HIGH" },
        { pattern = "setrawmetatable", name = "setrawmetatable", severity = "HIGH" },
        { pattern = "replaceclosure", name = "replaceclosure", severity = "CRITICAL" },
        { pattern = "__namecall%s*=", name = "__namecall override", severity = "CRITICAL" },
        { pattern = "__index%s*=", name = "__index override", severity = "HIGH" },
        { pattern = "__newindex%s*=", name = "__newindex override", severity = "HIGH" },
        { pattern = "setreadonly%s*%(", name = "setreadonly", severity = "HIGH" },
        { pattern = "getconnections", name = "getconnections", severity = "MEDIUM" },
    }

    for _, hp in ipairs(hookPatterns) do
        if code:find(hp.pattern) then
            patterns[#patterns + 1] = {
                pattern = hp.name,
                severity = hp.severity,
                source = source,
                description = string.format(
                    "Padrão de hooking '%s' encontrado em %s", hp.name, source or "unknown"
                ),
            }
        end
    end

    return patterns
end

--- Retorna hooks detectados
--- @return table
function HookDetector:getDetectedHooks()
    return self.detectedHooks
end

--- Retorna estatísticas
--- @return table
function HookDetector:getStats()
    return self.stats
end

--- Limpa detecções (mantém baseline)
function HookDetector:reset()
    self.detectedHooks = {}
    self.stats.total_checks = 0
    self.stats.hooks_detected = 0
end

return HookDetector
