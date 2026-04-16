--[[
    Scanning-Lua - Stealth Mode Module (#19)
    Modo invisível para operação discreta

    Features:
    - Não aparece no explorer
    - Não cria objetos visíveis
    - Executa silenciosamente
    - Nomes randomizados
    - Output bufferizado (não imprime no console diretamente)
]]

local StealthMode = {}
StealthMode.__index = StealthMode

--- Cria uma nova instância do modo stealth
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table StealthMode instance
function StealthMode.new(config, logger)
    local self = setmetatable({}, StealthMode)
    self.config = config or {}
    self.logger = logger
    self.enabled = false
    self.outputBuffer = {}
    self.hiddenInstances = {}
    self.originalPrint = print
    self.originalWarn = warn
    self.stats = {
        messages_buffered = 0,
        instances_hidden = 0,
    }
    return self
end

--- Gera um nome aleatório para evitar detecção
--- @param length number|nil Tamanho do nome (padrão: 8)
--- @return string Nome aleatório
function StealthMode.generateRandomName(length)
    length = length or 8
    local chars = "abcdefghijklmnopqrstuvwxyz"
    local result = {}
    for i = 1, length do
        local idx = math.random(1, #chars)
        result[i] = chars:sub(idx, idx)
    end
    return table.concat(result)
end

--- Ativa o modo stealth
function StealthMode:enable()
    if self.enabled then return end
    self.enabled = true

    -- Redirecionar output para buffer
    self:_enableOutputBuffering()

    -- Proteger instâncias criadas pelo scanner
    self:_enableInstanceProtection()

    if self.logger then
        self.logger:info("STEALTH", "Modo stealth ativado")
    end
end

--- Desativa o modo stealth
function StealthMode:disable()
    if not self.enabled then return end
    self.enabled = false

    -- Restaurar output
    self:_disableOutputBuffering()

    -- Restaurar instâncias
    self:_disableInstanceProtection()

    if self.logger then
        self.logger:info("STEALTH", "Modo stealth desativado")
    end
end

--- Habilita buffering de output (não imprime diretamente)
function StealthMode:_enableOutputBuffering()
    local selfRef = self

    -- Substituir print por versão silenciosa
    pcall(function()
        if self.config.BUFFER_OUTPUT then
            -- Salvar originais
            selfRef.originalPrint = print
            selfRef.originalWarn = warn

            -- Redirecionar para buffer
            _G.print = function(...)
                local args = { ... }
                local parts = {}
                for i = 1, #args do
                    parts[i] = tostring(args[i])
                end
                selfRef.outputBuffer[#selfRef.outputBuffer + 1] = {
                    type = "print",
                    message = table.concat(parts, "\t"),
                    timestamp = os.time(),
                }
                selfRef.stats.messages_buffered = selfRef.stats.messages_buffered + 1
            end
        end
    end)
end

--- Desabilita buffering e restaura output original
function StealthMode:_disableOutputBuffering()
    pcall(function()
        if self.originalPrint then
            _G.print = self.originalPrint
        end
        if self.originalWarn then
            _G.warn = self.originalWarn
        end
    end)
end

--- Protege instâncias criadas pelo scanner contra detecção
function StealthMode:_enableInstanceProtection()
    pcall(function()
        if not game then return end

        -- Proteger GUIs do scanner usando gethui (se disponível)
        if gethui then
            -- gethui() retorna o container de UI oculto
            -- Instâncias aqui não aparecem no explorer
            self.hiddenContainer = gethui()
        end

        -- Alternativa: usar syn.protect_gui
        if syn and syn.protect_gui then
            self.protectGui = syn.protect_gui
        end
    end)
end

--- Desabilita proteção de instâncias
function StealthMode:_disableInstanceProtection()
    -- Nada a restaurar - instâncias já criadas permanecem como estão
    self.hiddenContainer = nil
    self.protectGui = nil
end

--- Esconde uma instância do explorer (se possível)
--- @param instance any Instância a esconder
--- @return boolean success
function StealthMode:hideInstance(instance)
    if not self.enabled then return false end

    local hidden = false

    -- Método 1: Mover para hidden container
    pcall(function()
        if self.hiddenContainer then
            instance.Parent = self.hiddenContainer
            hidden = true
        end
    end)

    -- Método 2: Usar syn.protect_gui
    if not hidden then
        pcall(function()
            if self.protectGui then
                self.protectGui(instance)
                hidden = true
            end
        end)
    end

    -- Método 3: Renomear com nome aleatório
    if not hidden then
        pcall(function()
            instance.Name = StealthMode.generateRandomName(12)
            hidden = true
        end)
    end

    if hidden then
        self.hiddenInstances[#self.hiddenInstances + 1] = instance
        self.stats.instances_hidden = self.stats.instances_hidden + 1
    end

    return hidden
end

--- Cria uma instância de forma stealth (nome aleatório, sem visibilidade)
--- @param className string Classe da instância
--- @param parent any Parent da instância
--- @return any|nil Instância criada ou nil
function StealthMode:createStealthInstance(className, parent)
    local instance = nil

    pcall(function()
        if Instance and Instance.new then
            instance = Instance.new(className)
            instance.Name = StealthMode.generateRandomName(10)

            if parent then
                if self.hiddenContainer then
                    instance.Parent = self.hiddenContainer
                else
                    instance.Parent = parent
                end
            end
        end
    end)

    if instance then
        self.hiddenInstances[#self.hiddenInstances + 1] = instance
        self.stats.instances_hidden = self.stats.instances_hidden + 1
    end

    return instance
end

--- Flush do buffer de output (imprime tudo de uma vez)
--- @param useOriginalPrint boolean|nil Usar print original (padrão: true)
--- @return table Mensagens que estavam no buffer
function StealthMode:flushOutput(useOriginalPrint)
    local messages = {}
    local printFn = (useOriginalPrint ~= false) and self.originalPrint or print

    for _, entry in ipairs(self.outputBuffer) do
        messages[#messages + 1] = entry
        if printFn and self.config.FLUSH_TO_CONSOLE then
            printFn(entry.message)
        end
    end

    self.outputBuffer = {}
    return messages
end

--- Executa uma função em modo stealth (sem output visível)
--- @param fn function Função a executar
--- @return any Resultado da função
function StealthMode:executeQuietly(fn)
    local wasEnabled = self.enabled
    if not wasEnabled then self:enable() end

    local success, result = pcall(fn)

    if not wasEnabled then self:disable() end

    if success then
        return result
    else
        if self.logger then
            self.logger:error("STEALTH", "Erro em execução stealth: " .. tostring(result))
        end
        return nil
    end
end

--- Verifica se o modo stealth está ativo
--- @return boolean
function StealthMode:isEnabled()
    return self.enabled
end

--- Retorna estatísticas
--- @return table
function StealthMode:getStats()
    return {
        enabled = self.enabled,
        messages_buffered = self.stats.messages_buffered,
        instances_hidden = self.stats.instances_hidden,
        buffer_size = #self.outputBuffer,
    }
end

--- Limpa dados
function StealthMode:reset()
    self.outputBuffer = {}
    self.stats = {
        messages_buffered = 0,
        instances_hidden = 0,
    }
end

return StealthMode
