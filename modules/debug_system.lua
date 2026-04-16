--[[
    Scanning-Lua - Debug System Module (#20)
    Sistema de debug interno para desenvolvimento e diagnóstico

    Features:
    - Modo verbose (logging detalhado)
    - Logs com contexto profundo
    - Replay de eventos
    - Trace de execução
    - Métricas de performance
]]

local DebugSystem = {}
DebugSystem.__index = DebugSystem

--- Cria uma nova instância do sistema de debug
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table DebugSystem instance
function DebugSystem.new(config, logger)
    local self = setmetatable({}, DebugSystem)
    self.config = config or {}
    self.logger = logger
    self.verboseMode = config.VERBOSE_MODE or false
    self.eventLog = {}
    self.timers = {}
    self.performanceMetrics = {}
    self.maxEvents = config.MAX_EVENTS or 1000
    self.stats = {
        events_logged = 0,
        timers_created = 0,
        replays_executed = 0,
    }
    return self
end

--- Ativa/desativa modo verbose
--- @param enabled boolean
function DebugSystem:setVerbose(enabled)
    self.verboseMode = enabled
    if self.logger then
        self.logger:info("DEBUG_SYS", string.format(
            "Modo verbose: %s", enabled and "ATIVADO" or "DESATIVADO"
        ))
    end
end

--- Registra um evento no log de debug
--- @param category string Categoria do evento
--- @param eventType string Tipo do evento
--- @param data table|nil Dados associados
--- @param stackLevel number|nil Nível de stack trace (padrão: 2)
function DebugSystem:logEvent(category, eventType, data, stackLevel)
    local event = {
        id = #self.eventLog + 1,
        category = category,
        type = eventType,
        data = data,
        timestamp = os.time(),
        timestamp_iso = os.date("!%Y-%m-%dT%H:%M:%SZ"),
    }

    -- Adicionar stack trace se verbose
    if self.verboseMode then
        event.stack = debug.traceback("", stackLevel or 2)
    end

    -- Manter limite de eventos
    if #self.eventLog >= self.maxEvents then
        table.remove(self.eventLog, 1)
    end

    self.eventLog[#self.eventLog + 1] = event
    self.stats.events_logged = self.stats.events_logged + 1

    -- Output verbose
    if self.verboseMode and self.logger then
        self.logger:debug("DEBUG_SYS", string.format(
            "[%s:%s] %s", category, eventType, self:_formatData(data)
        ))
    end
end

--- Inicia um timer para medir performance
--- @param name string Nome do timer
--- @return number Timestamp de início
function DebugSystem:startTimer(name)
    local start = os.clock()
    self.timers[name] = {
        start = start,
        name = name,
    }
    self.stats.timers_created = self.stats.timers_created + 1
    return start
end

--- Para um timer e retorna o tempo decorrido
--- @param name string Nome do timer
--- @return number|nil Tempo decorrido em segundos
function DebugSystem:stopTimer(name)
    local timer = self.timers[name]
    if not timer then return nil end

    local elapsed = os.clock() - timer.start
    self.timers[name] = nil

    -- Registrar métrica de performance
    if not self.performanceMetrics[name] then
        self.performanceMetrics[name] = {
            name = name,
            executions = 0,
            total_time = 0,
            min_time = math.huge,
            max_time = 0,
        }
    end

    local metric = self.performanceMetrics[name]
    metric.executions = metric.executions + 1
    metric.total_time = metric.total_time + elapsed
    metric.average_time = metric.total_time / metric.executions
    if elapsed < metric.min_time then metric.min_time = elapsed end
    if elapsed > metric.max_time then metric.max_time = elapsed end

    -- Log se verbose
    if self.verboseMode and self.logger then
        self.logger:debug("DEBUG_SYS", string.format(
            "Timer '%s': %.4fs (avg: %.4fs, count: %d)",
            name, elapsed, metric.average_time, metric.executions
        ))
    end

    return elapsed
end

--- Executa replay dos eventos registrados
--- @param filter table|nil Filtro { category, type, from_time, to_time }
--- @return table Eventos filtrados
function DebugSystem:replayEvents(filter)
    self.stats.replays_executed = self.stats.replays_executed + 1

    local events = {}
    filter = filter or {}

    for _, event in ipairs(self.eventLog) do
        local include = true

        if filter.category and event.category ~= filter.category then
            include = false
        end
        if filter.type and event.type ~= filter.type then
            include = false
        end
        if filter.from_time and event.timestamp < filter.from_time then
            include = false
        end
        if filter.to_time and event.timestamp > filter.to_time then
            include = false
        end

        if include then
            events[#events + 1] = event
        end
    end

    if self.logger then
        self.logger:info("DEBUG_SYS", string.format(
            "Replay: %d eventos (filtro: %s)", #events, self:_formatData(filter)
        ))
    end

    return events
end

--- Retorna métricas de performance
--- @return table
function DebugSystem:getPerformanceMetrics()
    return self.performanceMetrics
end

--- Imprime resumo de performance formatado
function DebugSystem:printPerformanceSummary()
    local printFn = self.logger and function(msg) self.logger:info("PERF", msg) end or print

    printFn("=== Performance Summary ===")
    for name, metric in pairs(self.performanceMetrics) do
        printFn(string.format(
            "  %s: %d exec, avg %.4fs, min %.4fs, max %.4fs, total %.4fs",
            name, metric.executions, metric.average_time or 0,
            metric.min_time == math.huge and 0 or metric.min_time,
            metric.max_time, metric.total_time
        ))
    end
    printFn("========================")
end

--- Executa uma função com medição de tempo automática
--- @param name string Nome da operação
--- @param fn function Função a executar
--- @return any Resultado da função
function DebugSystem:measure(name, fn)
    self:startTimer(name)
    local success, result = pcall(fn)
    local elapsed = self:stopTimer(name)

    self:logEvent("PERFORMANCE", "MEASURE", {
        name = name,
        elapsed = elapsed,
        success = success,
    })

    if success then
        return result
    else
        if self.logger then
            self.logger:error("DEBUG_SYS", string.format(
                "Erro em '%s': %s (após %.4fs)", name, tostring(result), elapsed or 0
            ))
        end
        return nil
    end
end

--- Formata dados para display
--- @param data any
--- @return string
function DebugSystem:_formatData(data)
    if data == nil then return "nil" end
    if type(data) ~= "table" then return tostring(data) end

    local parts = {}
    for k, v in pairs(data) do
        parts[#parts + 1] = tostring(k) .. "=" .. tostring(v)
    end
    return "{" .. table.concat(parts, ", ") .. "}"
end

--- Retorna o log de eventos
--- @return table
function DebugSystem:getEventLog()
    return self.eventLog
end

--- Retorna estatísticas
--- @return table
function DebugSystem:getStats()
    return {
        events_logged = self.stats.events_logged,
        timers_created = self.stats.timers_created,
        replays_executed = self.stats.replays_executed,
        current_events = #self.eventLog,
        verbose_mode = self.verboseMode,
        active_timers = self:_countTimers(),
        performance_operations = self:_countMetrics(),
    }
end

function DebugSystem:_countTimers()
    local count = 0
    for _ in pairs(self.timers) do count = count + 1 end
    return count
end

function DebugSystem:_countMetrics()
    local count = 0
    for _ in pairs(self.performanceMetrics) do count = count + 1 end
    return count
end

--- Limpa tudo
function DebugSystem:reset()
    self.eventLog = {}
    self.timers = {}
    self.performanceMetrics = {}
    self.stats = {
        events_logged = 0,
        timers_created = 0,
        replays_executed = 0,
    }
end

return DebugSystem
