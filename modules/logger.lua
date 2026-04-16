--[[
    Scanning-Lua - Logger Module
    Sistema de logging com saída em JSON
    Suporta múltiplos níveis de severidade e persistência em arquivo
]]

local JSON = require("modules.json")

local Logger = {}
Logger.__index = Logger

-- Níveis de log com prioridade numérica
local LOG_LEVELS = {
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5,
}

--- Cria uma nova instância do Logger
--- @param config table Configurações do logger (de Config.Logger)
--- @param logDir string Diretório para salvar logs
--- @return table Logger instance
function Logger.new(config, logDir)
    local self = setmetatable({}, Logger)
    self.config = config or {}
    self.logDir = logDir or "logs"
    self.minLevel = LOG_LEVELS[config.MIN_LEVEL] or LOG_LEVELS.DEBUG
    self.entries = {}
    self.sessionId = Logger._generateSessionId()
    self.startTime = os.time()
    self.entryCount = 0

    -- Metadados da sessão
    self.sessionMeta = {
        session_id = self.sessionId,
        start_time = os.date("!%Y-%m-%dT%H:%M:%SZ", self.startTime),
        scanner_version = "1.0.0",
        log_level = config.MIN_LEVEL or "DEBUG",
    }

    return self
end

--- Gera um ID de sessão único
--- @return string
function Logger._generateSessionId()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    local result = string.gsub(template, "[xy]", function(c)
        local v = (c == "x") and math.random(0, 15) or math.random(8, 11)
        return string.format("%x", v)
    end)
    return result
end

--- Retorna o timestamp atual em formato ISO 8601
--- @return string
function Logger._getTimestamp()
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

--- Cria uma entrada de log estruturada
--- @param level string Nível de log
--- @param category string Categoria do log
--- @param message string Mensagem
--- @param data table|nil Dados adicionais
--- @return table Entrada de log
function Logger:_createEntry(level, category, message, data)
    self.entryCount = self.entryCount + 1
    local entry = {
        id = self.entryCount,
        timestamp = Logger._getTimestamp(),
        level = level,
        category = category,
        message = message,
        session_id = self.sessionId,
    }
    if data then
        entry.data = data
    end
    if self.config.INCLUDE_STACKTRACE and (level == "ERROR" or level == "CRITICAL") then
        entry.stacktrace = debug.traceback("", 3)
    end
    return entry
end

--- Registra uma entrada de log se o nível atender ao mínimo configurado
--- @param level string Nível de log
--- @param category string Categoria
--- @param message string Mensagem
--- @param data table|nil Dados adicionais
function Logger:_log(level, category, message, data)
    local levelNum = LOG_LEVELS[level]
    if not levelNum or levelNum < self.minLevel then
        return
    end

    local entry = self:_createEntry(level, category, message, data)
    self.entries[#self.entries + 1] = entry

    -- Output no console
    local prefix = string.format("[%s][%s][%s]", entry.timestamp, level, category)
    print(prefix .. " " .. message)

    -- Verificar limite de entradas
    if self.config.MAX_ENTRIES_PER_FILE and #self.entries >= self.config.MAX_ENTRIES_PER_FILE then
        self:flush()
    end

    return entry
end

--- Log nível DEBUG
--- @param category string Categoria
--- @param message string Mensagem
--- @param data table|nil Dados adicionais
function Logger:debug(category, message, data)
    return self:_log("DEBUG", category, message, data)
end

--- Log nível INFO
--- @param category string Categoria
--- @param message string Mensagem
--- @param data table|nil Dados adicionais
function Logger:info(category, message, data)
    return self:_log("INFO", category, message, data)
end

--- Log nível WARN
--- @param category string Categoria
--- @param message string Mensagem
--- @param data table|nil Dados adicionais
function Logger:warn(category, message, data)
    return self:_log("WARN", category, message, data)
end

--- Log nível ERROR
--- @param category string Categoria
--- @param message string Mensagem
--- @param data table|nil Dados adicionais
function Logger:error(category, message, data)
    return self:_log("ERROR", category, message, data)
end

--- Log nível CRITICAL
--- @param category string Categoria
--- @param message string Mensagem
--- @param data table|nil Dados adicionais
function Logger:critical(category, message, data)
    return self:_log("CRITICAL", category, message, data)
end

--- Salva as entradas de log atuais em um arquivo JSON
--- @param filename string|nil Nome do arquivo (opcional)
--- @return boolean success
--- @return string|nil error
function Logger:flush(filename)
    if #self.entries == 0 then
        return true
    end

    if not self.config.SAVE_TO_FILE then
        return true
    end

    local fname = filename or string.format(
        "%s/%s_%s.json",
        self.logDir,
        self.config.FILE_PREFIX or "scan_log",
        os.date("!%Y%m%d_%H%M%S")
    )

    local logData = {
        metadata = self.sessionMeta,
        total_entries = #self.entries,
        entries = self.entries,
    }

    local jsonStr = JSON.encodePretty(logData)

    local file, err = io.open(fname, "w")
    if not file then
        print("[Logger] Erro ao abrir arquivo: " .. tostring(err))
        return false, err
    end

    file:write(jsonStr)
    file:close()

    print(string.format("[Logger] %d entradas salvas em: %s", #self.entries, fname))

    -- Limpar entradas após salvar
    self.entries = {}
    self.entryCount = 0

    return true
end

--- Retorna todas as entradas de log como tabela
--- @return table
function Logger:getEntries()
    return self.entries
end

--- Retorna as entradas de log como string JSON
--- @return string
function Logger:toJSON()
    local logData = {
        metadata = self.sessionMeta,
        total_entries = #self.entries,
        entries = self.entries,
    }
    return JSON.encodePretty(logData)
end

--- Retorna estatísticas do logger
--- @return table
function Logger:getStats()
    local stats = {
        session_id = self.sessionId,
        total_entries = #self.entries,
        by_level = {
            DEBUG = 0,
            INFO = 0,
            WARN = 0,
            ERROR = 0,
            CRITICAL = 0,
        },
    }
    for _, entry in ipairs(self.entries) do
        if stats.by_level[entry.level] then
            stats.by_level[entry.level] = stats.by_level[entry.level] + 1
        end
    end
    return stats
end

--- Finaliza o logger e salva todos os logs pendentes
function Logger:close()
    self:info("LOGGER", "Encerrando sessão de log", {
        session_id = self.sessionId,
        duration_seconds = os.time() - self.startTime,
        total_entries = #self.entries,
    })
    self:flush()
end

return Logger
