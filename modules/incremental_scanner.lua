--[[
    Scanning-Lua - Incremental Scanner Module (#15)
    Scanner incremental para ganho de performance

    Em vez de escanear tudo sempre:
    - Guarda hash de cada script analisado
    - Só reanalisar se o hash mudou
    - Mantém cache de resultados anteriores
    - Ganho enorme de performance em scans repetidos
]]

local IncrementalScanner = {}
IncrementalScanner.__index = IncrementalScanner

--- Cria uma nova instância do scanner incremental
--- @param logger table Instância do Logger
--- @return table IncrementalScanner instance
function IncrementalScanner.new(logger)
    local self = setmetatable({}, IncrementalScanner)
    self.logger = logger
    self.hashCache = {}      -- { [scriptPath] = { hash = "...", lastScan = timestamp, results = {...} } }
    self.stats = {
        total_checks = 0,
        cache_hits = 0,
        cache_misses = 0,
        rescans = 0,
        scripts_tracked = 0,
    }
    return self
end

--- Calcula hash de um código/script (DJB2)
--- @param code string Código do script
--- @return string Hash hexadecimal
function IncrementalScanner.computeHash(code)
    if type(code) ~= "string" then return "nil" end

    local hash = 5381
    for i = 1, #code do
        hash = ((hash * 33) + code:byte(i)) % 2147483647
    end
    return string.format("%08x", hash)
end

--- Verifica se um script precisa ser reanalisado
--- @param scriptPath string Caminho/identificador do script
--- @param code string Código atual do script
--- @return boolean needsRescan true se o script mudou ou nunca foi analisado
--- @return table|nil cachedResults Resultados em cache se não mudou
function IncrementalScanner:needsRescan(scriptPath, code)
    self.stats.total_checks = self.stats.total_checks + 1

    local newHash = IncrementalScanner.computeHash(code)
    local cached = self.hashCache[scriptPath]

    if cached and cached.hash == newHash then
        -- Hash igual → script não mudou → usar cache
        self.stats.cache_hits = self.stats.cache_hits + 1

        if self.logger then
            self.logger:debug("INCREMENTAL", string.format(
                "Cache hit: %s (hash: %s)", scriptPath, newHash
            ))
        end

        return false, cached.results
    end

    -- Hash diferente ou primeiro scan
    self.stats.cache_misses = self.stats.cache_misses + 1

    if cached then
        self.stats.rescans = self.stats.rescans + 1
        if self.logger then
            self.logger:info("INCREMENTAL", string.format(
                "Script modificado: %s (hash: %s → %s)", scriptPath, cached.hash, newHash
            ))
        end
    else
        if self.logger then
            self.logger:debug("INCREMENTAL", string.format(
                "Novo script: %s (hash: %s)", scriptPath, newHash
            ))
        end
    end

    return true, nil
end

--- Atualiza o cache com o resultado de um scan
--- @param scriptPath string Caminho/identificador do script
--- @param code string Código do script
--- @param results table Resultados do scan
function IncrementalScanner:updateCache(scriptPath, code, results)
    local hash = IncrementalScanner.computeHash(code)

    if not self.hashCache[scriptPath] then
        self.stats.scripts_tracked = self.stats.scripts_tracked + 1
    end

    self.hashCache[scriptPath] = {
        hash = hash,
        lastScan = os.time(),
        lastScanISO = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        codeLength = #code,
        results = results,
    }
end

--- Remove um script do cache
--- @param scriptPath string Caminho/identificador do script
function IncrementalScanner:invalidate(scriptPath)
    if self.hashCache[scriptPath] then
        self.hashCache[scriptPath] = nil
        self.stats.scripts_tracked = self.stats.scripts_tracked - 1

        if self.logger then
            self.logger:debug("INCREMENTAL", string.format(
                "Cache invalidado: %s", scriptPath
            ))
        end
    end
end

--- Limpa todo o cache
function IncrementalScanner:clearCache()
    local count = self.stats.scripts_tracked
    self.hashCache = {}
    self.stats.scripts_tracked = 0

    if self.logger then
        self.logger:info("INCREMENTAL", string.format(
            "Cache limpo: %d entradas removidas", count
        ))
    end
end

--- Retorna informações do cache para um script
--- @param scriptPath string
--- @return table|nil Informações do cache
function IncrementalScanner:getCacheInfo(scriptPath)
    return self.hashCache[scriptPath]
end

--- Retorna taxa de cache hit
--- @return number Percentual de cache hits (0-100)
function IncrementalScanner:getCacheHitRate()
    local total = self.stats.cache_hits + self.stats.cache_misses
    if total == 0 then return 0 end
    return math.floor((self.stats.cache_hits / total) * 100)
end

--- Retorna estatísticas
--- @return table
function IncrementalScanner:getStats()
    local stats = {
        total_checks = self.stats.total_checks,
        cache_hits = self.stats.cache_hits,
        cache_misses = self.stats.cache_misses,
        rescans = self.stats.rescans,
        scripts_tracked = self.stats.scripts_tracked,
        cache_hit_rate = self:getCacheHitRate(),
    }
    return stats
end

--- Limpa tudo
function IncrementalScanner:reset()
    self.hashCache = {}
    self.stats = {
        total_checks = 0,
        cache_hits = 0,
        cache_misses = 0,
        rescans = 0,
        scripts_tracked = 0,
    }
end

return IncrementalScanner
