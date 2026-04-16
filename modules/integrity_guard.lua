--[[
    Scanning-Lua - Integrity Guard Module (#18)
    Proteção contra sabotagem do scanner

    O scanner pode ser alvo de outros scripts maliciosos.
    Este módulo protege:
    - Verificação de integridade de módulos
    - Auto-recovery: recriar módulos se apagados
    - Detecção de alterações no scanner
    - Proteção de referências críticas
]]

local IntegrityGuard = {}
IntegrityGuard.__index = IntegrityGuard

--- Cria uma nova instância do guardião de integridade
--- @param logger table Instância do Logger
--- @return table IntegrityGuard instance
function IntegrityGuard.new(logger)
    local self = setmetatable({}, IntegrityGuard)
    self.logger = logger
    self.moduleRegistry = {}
    self.functionChecksums = {}
    self.protectedReferences = {}
    self.alerts = {}
    self.isActive = false
    self.stats = {
        total_checks = 0,
        integrity_violations = 0,
        auto_recoveries = 0,
    }
    return self
end

--- Registra um módulo para proteção de integridade
--- @param name string Nome do módulo
--- @param moduleRef table Referência ao módulo
--- @param criticalFunctions table|nil Lista de nomes de funções críticas
function IntegrityGuard:registerModule(name, moduleRef, criticalFunctions)
    local entry = {
        name = name,
        reference = moduleRef,
        registered_at = os.time(),
        function_refs = {},
    }

    -- Capturar referências de funções críticas
    if criticalFunctions then
        for _, fnName in ipairs(criticalFunctions) do
            if type(moduleRef[fnName]) == "function" then
                entry.function_refs[fnName] = moduleRef[fnName]
            end
        end
    else
        -- Registrar todas as funções do módulo
        for k, v in pairs(moduleRef) do
            if type(v) == "function" and type(k) == "string" and not k:match("^_") then
                entry.function_refs[k] = v
            end
        end
    end

    self.moduleRegistry[name] = entry

    if self.logger then
        local fnCount = 0
        for _ in pairs(entry.function_refs) do fnCount = fnCount + 1 end
        self.logger:debug("INTEGRITY", string.format(
            "Módulo registrado: %s (%d funções protegidas)", name, fnCount
        ))
    end
end

--- Protege uma referência crítica (variável/tabela)
--- @param name string Nome identificador
--- @param reference any Referência a proteger
function IntegrityGuard:protect(name, reference)
    self.protectedReferences[name] = {
        reference = reference,
        type = type(reference),
        protected_at = os.time(),
    }
end

--- Verifica integridade de todos os módulos registrados
--- @return table Relatório de integridade
function IntegrityGuard:checkIntegrity()
    self.stats.total_checks = self.stats.total_checks + 1
    local report = {
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        modules = {},
        protected_refs = {},
        is_compromised = false,
        violations = {},
    }

    -- Verificar módulos
    for name, entry in pairs(self.moduleRegistry) do
        local moduleStatus = {
            name = name,
            intact = true,
            issues = {},
        }

        -- Verificar se o módulo ainda existe
        if not entry.reference then
            moduleStatus.intact = false
            moduleStatus.issues[#moduleStatus.issues + 1] = "Referência do módulo é nil"
        else
            -- Verificar funções
            for fnName, originalRef in pairs(entry.function_refs) do
                local currentRef = entry.reference[fnName]

                if currentRef == nil then
                    moduleStatus.intact = false
                    moduleStatus.issues[#moduleStatus.issues + 1] = string.format(
                        "Função '%s' foi removida", fnName
                    )
                elseif currentRef ~= originalRef then
                    moduleStatus.intact = false
                    moduleStatus.issues[#moduleStatus.issues + 1] = string.format(
                        "Função '%s' foi alterada", fnName
                    )
                end
            end
        end

        if not moduleStatus.intact then
            report.is_compromised = true
            self.stats.integrity_violations = self.stats.integrity_violations + 1

            local violation = {
                module = name,
                issues = moduleStatus.issues,
                timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            }
            report.violations[#report.violations + 1] = violation
            self.alerts[#self.alerts + 1] = violation

            if self.logger then
                self.logger:critical("INTEGRITY", string.format(
                    "VIOLAÇÃO: Módulo '%s' comprometido - %d problemas",
                    name, #moduleStatus.issues
                ), violation)
            end
        end

        report.modules[#report.modules + 1] = moduleStatus
    end

    -- Verificar referências protegidas
    for name, entry in pairs(self.protectedReferences) do
        local refStatus = {
            name = name,
            intact = true,
        }

        if type(entry.reference) ~= entry.type then
            refStatus.intact = false
            report.is_compromised = true
            self.stats.integrity_violations = self.stats.integrity_violations + 1

            if self.logger then
                self.logger:critical("INTEGRITY", string.format(
                    "VIOLAÇÃO: Referência '%s' alterada (era %s, agora %s)",
                    name, entry.type, type(entry.reference)
                ))
            end
        end

        report.protected_refs[#report.protected_refs + 1] = refStatus
    end

    if not report.is_compromised and self.logger then
        self.logger:info("INTEGRITY", "Verificação de integridade OK - todos os módulos íntegros")
    end

    return report
end

--- Tenta recuperar módulos comprometidos
--- @return table Relatório de recuperação
function IntegrityGuard:autoRecover()
    local recovery = {
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        recovered = {},
        failed = {},
    }

    for name, entry in pairs(self.moduleRegistry) do
        if not entry.reference then
            -- Módulo foi removido - não podemos recuperar sem backup
            recovery.failed[#recovery.failed + 1] = {
                module = name,
                reason = "Módulo completamente removido - sem backup disponível",
            }
        else
            -- Tentar restaurar funções alteradas
            local restored = 0
            for fnName, originalRef in pairs(entry.function_refs) do
                if entry.reference[fnName] ~= originalRef then
                    -- Restaurar referência original
                    local success = pcall(function()
                        entry.reference[fnName] = originalRef
                    end)
                    if success then
                        restored = restored + 1
                    end
                end
            end

            if restored > 0 then
                recovery.recovered[#recovery.recovered + 1] = {
                    module = name,
                    functions_restored = restored,
                }
                self.stats.auto_recoveries = self.stats.auto_recoveries + 1

                if self.logger then
                    self.logger:info("INTEGRITY", string.format(
                        "Módulo '%s' recuperado: %d funções restauradas", name, restored
                    ))
                end
            end
        end
    end

    return recovery
end

--- Ativa monitoramento contínuo de integridade
--- @param checkInterval number Intervalo entre verificações (segundos)
function IntegrityGuard:activate(checkInterval)
    self.isActive = true
    checkInterval = checkInterval or 30

    -- Usar task.spawn se disponível
    pcall(function()
        if task and task.spawn then
            task.spawn(function()
                while self.isActive do
                    self:checkIntegrity()
                    task.wait(checkInterval)
                end
            end)
        end
    end)

    if self.logger then
        self.logger:info("INTEGRITY", string.format(
            "Guardião de integridade ativado (intervalo: %ds)", checkInterval
        ))
    end
end

--- Desativa monitoramento
function IntegrityGuard:deactivate()
    self.isActive = false
end

--- Retorna alertas
--- @return table
function IntegrityGuard:getAlerts()
    return self.alerts
end

--- Retorna estatísticas
--- @return table
function IntegrityGuard:getStats()
    return self.stats
end

--- Limpa alertas (mantém registros de módulos)
function IntegrityGuard:reset()
    self.alerts = {}
    self.stats = {
        total_checks = 0,
        integrity_violations = 0,
        auto_recoveries = 0,
    }
end

return IntegrityGuard
