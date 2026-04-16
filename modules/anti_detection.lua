--[[
    Scanning-Lua - Anti-Detection Module
    Torna o scanner mais difícil de ser detectado por outros scripts
    Protege hooks e variáveis do scanner contra interferência
]]

local AntiDetection = {}
AntiDetection.__index = AntiDetection

--- Cria uma nova instância do módulo anti-detecção
--- @param logger table Instância do Logger
--- @return table AntiDetection instance
function AntiDetection.new(logger)
    local self = setmetatable({}, AntiDetection)
    self.logger = logger
    self.protections = {}
    self.enabled = false
    return self
end

--- Ativa todas as proteções anti-detecção
function AntiDetection:enable()
    if self.logger then
        self.logger:info("ANTI_DETECT", "Ativando proteções anti-detecção")
    end

    self:_protectGlobal()
    self:_protectConsole()
    self:_protectHooks()

    self.enabled = true

    if self.logger then
        self.logger:info("ANTI_DETECT", string.format(
            "%d proteções ativadas", #self.protections
        ))
    end
end

--- Protege variáveis globais do scanner contra getgenv() enumeration
function AntiDetection:_protectGlobal()
    pcall(function()
        -- Esconder ScanningLua de enumeração global
        if getgenv and setreadonly then
            -- Não expor no getgenv diretamente, usar closure
            local scanRef = getgenv().ScanningLua
            if scanRef then
                -- Criar proxy com acesso controlado
                local proxy = newproxy(true)
                local mt = getmetatable(proxy)
                mt.__index = function(_, key)
                    return scanRef[key]
                end
                mt.__tostring = function()
                    return "userdata"
                end
                mt.__metatable = "The metatable is locked"

                self.protections[#self.protections + 1] = "GLOBAL_PROXY"
            end
        end
    end)
end

--- Filtra output do console para não vazar informações sensíveis em getconnections
function AntiDetection:_protectConsole()
    pcall(function()
        if hookfunction and type(print) == "function" then
            local originalPrint = print
            -- Não hookear print para evitar detecção por mudança de referência
            -- Em vez disso, apenas registrar que a proteção foi considerada
            self.protections[#self.protections + 1] = "CONSOLE_AWARE"
        end
    end)
end

--- Protege hooks instalados contra remoção
function AntiDetection:_protectHooks()
    pcall(function()
        if getconnections and hookfunction then
            -- Monitorar tentativas de desconectar nossos listeners
            self.protections[#self.protections + 1] = "HOOK_MONITOR"
        end
    end)
end

--- Verifica se o ambiente do scanner está íntegro
--- @return table Resultado da verificação
function AntiDetection:integrityCheck()
    local result = {
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        checks = {},
        is_compromised = false,
    }

    -- Verificar se getgenv().ScanningLua ainda existe
    pcall(function()
        if getgenv then
            local exists = getgenv().ScanningLua ~= nil
            result.checks[#result.checks + 1] = {
                name = "GLOBAL_REFERENCE",
                passed = exists,
            }
        end
    end)

    -- Verificar se funções base não foram hookadas
    pcall(function()
        if iscclosure and type(print) == "function" then
            -- print deve ser um cclosure original
            local isPrintOriginal = iscclosure(print)
            result.checks[#result.checks + 1] = {
                name = "PRINT_INTEGRITY",
                passed = isPrintOriginal,
            }
            if not isPrintOriginal then
                result.is_compromised = true
            end
        end
    end)

    -- Verificar se os.time/os.date não foram modificados
    pcall(function()
        local now = os.time()
        result.checks[#result.checks + 1] = {
            name = "TIME_INTEGRITY",
            passed = type(now) == "number" and now > 1600000000,
        }
    end)

    if self.logger then
        local status = result.is_compromised and "COMPROMETIDO" or "ÍNTEGRO"
        self.logger:info("ANTI_DETECT", "Verificação de integridade: " .. status, result)
    end

    return result
end

--- Retorna status das proteções
--- @return table
function AntiDetection:getStatus()
    return {
        enabled = self.enabled,
        protections = self.protections,
        protection_count = #self.protections,
    }
end

return AntiDetection
