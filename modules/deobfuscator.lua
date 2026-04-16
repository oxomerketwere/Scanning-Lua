--[[
    Scanning-Lua - Deobfuscator Module (#12)
    Deobfuscação básica de código Lua (nível avançado)

    Capacidades:
    - Juntar strings concatenadas: "ab".."cd" → "abcd"
    - Decodificar base64
    - Resolver string.char(...) para texto
    - Remover junk code (variáveis não usadas, dead code)
    - Resolver hex/octal escapes em strings
]]

local Deobfuscator = {}
Deobfuscator.__index = Deobfuscator

-- Tabela base64 padrão
local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

--- Cria uma nova instância do Deobfuscator
--- @param logger table Instância do Logger
--- @return table Deobfuscator instance
function Deobfuscator.new(logger)
    local self = setmetatable({}, Deobfuscator)
    self.logger = logger
    self.stats = {
        total_processed = 0,
        strings_joined = 0,
        base64_decoded = 0,
        string_char_resolved = 0,
        hex_resolved = 0,
        junk_removed = 0,
    }
    return self
end

--- Executa todas as deobfuscações no código
--- @param code string Código a deobfuscar
--- @param source string Identificador da origem
--- @return string Código deobfuscado (parcial)
--- @return table Relatório de transformações aplicadas
function Deobfuscator:deobfuscate(code, source)
    if type(code) ~= "string" then return code, {} end

    self.stats.total_processed = self.stats.total_processed + 1
    source = source or "unknown"
    local transformations = {}
    local result = code

    -- 1. Resolver hex escapes: \x41 → A
    local hexResult, hexCount = self:resolveHexEscapes(result)
    if hexCount > 0 then
        result = hexResult
        transformations[#transformations + 1] = {
            type = "HEX_RESOLVE",
            count = hexCount,
            description = string.format("Resolvidos %d hex escapes", hexCount),
        }
    end

    -- 2. Resolver octal escapes: \097 → a
    local octalResult, octalCount = self:resolveOctalEscapes(result)
    if octalCount > 0 then
        result = octalResult
        transformations[#transformations + 1] = {
            type = "OCTAL_RESOLVE",
            count = octalCount,
            description = string.format("Resolvidos %d octal escapes", octalCount),
        }
    end

    -- 3. Juntar strings concatenadas: "ab".."cd" → "abcd"
    local concatResult, concatCount = self:joinConcatenatedStrings(result)
    if concatCount > 0 then
        result = concatResult
        transformations[#transformations + 1] = {
            type = "STRING_JOIN",
            count = concatCount,
            description = string.format("Unidas %d concatenações de string", concatCount),
        }
    end

    -- 4. Resolver string.char(...) → texto
    local charResult, charCount = self:resolveStringChar(result)
    if charCount > 0 then
        result = charResult
        transformations[#transformations + 1] = {
            type = "STRING_CHAR_RESOLVE",
            count = charCount,
            description = string.format("Resolvidas %d chamadas string.char", charCount),
        }
    end

    -- 5. Detectar e decodificar base64
    local b64Detections = self:detectBase64(result)
    if #b64Detections > 0 then
        transformations[#transformations + 1] = {
            type = "BASE64_DETECT",
            count = #b64Detections,
            detections = b64Detections,
            description = string.format("Detectadas %d strings base64", #b64Detections),
        }
    end

    -- 6. Identificar junk code
    local junkPatterns = self:identifyJunkCode(result)
    if #junkPatterns > 0 then
        transformations[#transformations + 1] = {
            type = "JUNK_CODE_IDENTIFIED",
            count = #junkPatterns,
            patterns = junkPatterns,
            description = string.format("Identificados %d padrões de junk code", #junkPatterns),
        }
    end

    if self.logger and #transformations > 0 then
        self.logger:info("DEOBFUSCATOR", string.format(
            "%d transformações aplicadas em %s", #transformations, source
        ))
    end

    return result, transformations
end

--- Junta strings concatenadas adjacentes
--- Transforma: "abc" .. "def" → "abcdef"
--- @param code string
--- @return string, number Código transformado e número de junções
function Deobfuscator:joinConcatenatedStrings(code)
    local count = 0
    local result = code

    -- Pattern: "string1" .. "string2"
    -- Suporta aspas simples e duplas
    local changed = true
    local maxIterations = 100 -- Prevenir loop infinito
    local iteration = 0

    while changed and iteration < maxIterations do
        changed = false
        iteration = iteration + 1

        -- Aspas duplas: "abc" .. "def"
        local newResult = result:gsub('"([^"]*)"(%s*%.%.%s*)"([^"]*)"', function(s1, _, s2)
            changed = true
            count = count + 1
            return '"' .. s1 .. s2 .. '"'
        end)
        result = newResult

        -- Aspas simples: 'abc' .. 'def'
        newResult = result:gsub("'([^']*)'(%s*%.%.%s*)'([^']*)'", function(s1, _, s2)
            changed = true
            count = count + 1
            return "'" .. s1 .. s2 .. "'"
        end)
        result = newResult
    end

    self.stats.strings_joined = self.stats.strings_joined + count
    return result, count
end

--- Resolve hex escapes em strings: \x41 → A
--- @param code string
--- @return string, number Código transformado e número de resoluções
function Deobfuscator:resolveHexEscapes(code)
    local count = 0
    local result = code:gsub("\\x(%x%x)", function(hex)
        local byte = tonumber(hex, 16)
        if byte and byte >= 32 and byte <= 126 then
            count = count + 1
            return string.char(byte)
        end
        return "\\x" .. hex
    end)
    self.stats.hex_resolved = self.stats.hex_resolved + count
    return result, count
end

--- Resolve octal escapes em strings: \097 → a
--- @param code string
--- @return string, number Código transformado e número de resoluções
function Deobfuscator:resolveOctalEscapes(code)
    local count = 0
    local result = code:gsub("\\(%d%d%d)", function(oct)
        local byte = tonumber(oct)
        if byte and byte >= 32 and byte <= 255 then
            if byte <= 126 then
                count = count + 1
                return string.char(byte)
            end
        end
        return "\\" .. oct
    end)
    return result, count
end

--- Resolve chamadas string.char(...) para o texto resultante
--- Transforma: string.char(72,101,108,108,111) → "Hello"
--- @param code string
--- @return string, number Código transformado e número de resoluções
function Deobfuscator:resolveStringChar(code)
    local count = 0
    local result = code:gsub("string%.char%(([%d%s,]+)%)", function(args)
        local chars = {}
        for numStr in args:gmatch("%d+") do
            local num = tonumber(numStr)
            if num and num >= 0 and num <= 127 then
                chars[#chars + 1] = string.char(num)
            else
                return "string.char(" .. args .. ")" -- Não resolver se inválido
            end
        end
        if #chars > 0 then
            count = count + 1
            return '"' .. table.concat(chars) .. '"'
        end
        return "string.char(" .. args .. ")"
    end)
    self.stats.string_char_resolved = self.stats.string_char_resolved + count
    return result, count
end

--- Decodifica uma string base64
--- @param data string String codificada em base64
--- @return string|nil String decodificada ou nil se inválido
function Deobfuscator:decodeBase64(data)
    if type(data) ~= "string" then return nil end

    -- Remover whitespace
    data = data:gsub("%s", "")
    if #data == 0 then return nil end

    -- Verificar se é base64 válido
    if not data:match("^[A-Za-z0-9+/]+=*$") then return nil end

    local result = {}
    local padding = data:match("(=*)$")
    data = data:gsub("=", "")

    for i = 1, #data, 4 do
        local a = B64_CHARS:find(data:sub(i, i))
        local b = B64_CHARS:find(data:sub(i + 1, i + 1))
        local c = B64_CHARS:find(data:sub(i + 2, i + 2))
        local d = B64_CHARS:find(data:sub(i + 3, i + 3))

        if not a or not b then return nil end -- Invalid base64
        a, b = a - 1, b - 1
        c = c and (c - 1) or 0
        d = d and (d - 1) or 0

        local n = a * 262144 + b * 4096 + c * 64 + d

        result[#result + 1] = string.char(math.floor(n / 65536) % 256)
        if i + 1 <= #data then
            result[#result + 1] = string.char(math.floor(n / 256) % 256)
        end
        if i + 2 <= #data then
            result[#result + 1] = string.char(n % 256)
        end
    end

    local decoded = table.concat(result)

    -- Verificar se resultado é texto legível
    local printableCount = 0
    for i = 1, #decoded do
        local byte = decoded:byte(i)
        if byte >= 32 and byte <= 126 or byte == 10 or byte == 13 or byte == 9 then
            printableCount = printableCount + 1
        end
    end

    if printableCount / math.max(#decoded, 1) < 0.7 then
        return nil -- Não é texto legível
    end

    return decoded
end

--- Detecta strings base64 no código e tenta decodificá-las
--- @param code string
--- @return table Lista de detecções com decodificação
function Deobfuscator:detectBase64(code)
    local detections = {}

    -- Procurar strings longas que parecem base64
    for str in code:gmatch('"([A-Za-z0-9+/]+=*)"') do
        if #str >= 20 then
            local decoded = self:decodeBase64(str)
            if decoded then
                detections[#detections + 1] = {
                    encoded = str:sub(1, 50) .. (#str > 50 and "..." or ""),
                    encoded_length = #str,
                    decoded = decoded:sub(1, 200) .. (#decoded > 200 and "..." or ""),
                    decoded_length = #decoded,
                }
                self.stats.base64_decoded = self.stats.base64_decoded + 1
            end
        end
    end

    -- Aspas simples
    for str in code:gmatch("'([A-Za-z0-9+/]+=*)'") do
        if #str >= 20 then
            local decoded = self:decodeBase64(str)
            if decoded then
                detections[#detections + 1] = {
                    encoded = str:sub(1, 50) .. (#str > 50 and "..." or ""),
                    encoded_length = #str,
                    decoded = decoded:sub(1, 200) .. (#decoded > 200 and "..." or ""),
                    decoded_length = #decoded,
                }
                self.stats.base64_decoded = self.stats.base64_decoded + 1
            end
        end
    end

    return detections
end

--- Identifica padrões de junk code (código morto/inútil)
--- @param code string
--- @return table Lista de padrões de junk identificados
function Deobfuscator:identifyJunkCode(code)
    local patterns = {}

    -- Variáveis atribuídas mas nunca usadas (heurística)
    local varDeclCount = 0
    for _ in code:gmatch("local%s+_[%w]+%s*=") do
        varDeclCount = varDeclCount + 1
    end
    if varDeclCount >= 10 then
        patterns[#patterns + 1] = {
            type = "UNUSED_UNDERSCORE_VARS",
            count = varDeclCount,
            description = string.format(
                "%d variáveis com prefixo _ (possível junk code)", varDeclCount
            ),
        }
        self.stats.junk_removed = self.stats.junk_removed + varDeclCount
    end

    -- Operações matemáticas sem efeito (junk ops)
    local junkMathCount = 0
    for _ in code:gmatch("local%s+[%w_]+%s*=%s*%d+%s*[%+%-%*]%s*%d+%s*[%+%-%*]%s*%d+") do
        junkMathCount = junkMathCount + 1
    end
    if junkMathCount >= 5 then
        patterns[#patterns + 1] = {
            type = "JUNK_MATH_OPERATIONS",
            count = junkMathCount,
            description = string.format(
                "%d operações matemáticas complexas (possível junk)", junkMathCount
            ),
        }
    end

    -- If-else com condições sempre verdadeiras/falsas
    for _ in code:gmatch("if%s+true%s+then") do
        patterns[#patterns + 1] = {
            type = "ALWAYS_TRUE_CONDITION",
            description = "Condição 'if true then' - possível dead code",
        }
    end
    for _ in code:gmatch("if%s+false%s+then") do
        patterns[#patterns + 1] = {
            type = "ALWAYS_FALSE_CONDITION",
            description = "Condição 'if false then' - dead code",
        }
    end

    -- Funções vazias
    local emptyFuncCount = 0
    for _ in code:gmatch("function%s*[%w_%.]*%s*%(.-%)%s*end") do
        emptyFuncCount = emptyFuncCount + 1
    end
    if emptyFuncCount >= 5 then
        patterns[#patterns + 1] = {
            type = "EMPTY_FUNCTIONS",
            count = emptyFuncCount,
            description = string.format(
                "%d funções potencialmente vazias (possível junk code)", emptyFuncCount
            ),
        }
    end

    return patterns
end

--- Retorna estatísticas
--- @return table
function Deobfuscator:getStats()
    return self.stats
end

--- Limpa estatísticas
function Deobfuscator:reset()
    self.stats = {
        total_processed = 0,
        strings_joined = 0,
        base64_decoded = 0,
        string_char_resolved = 0,
        hex_resolved = 0,
        junk_removed = 0,
    }
end

return Deobfuscator
