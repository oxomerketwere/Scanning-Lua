--[[
    Scanning-Lua - JSON Module
    Módulo utilitário para serialização/deserialização JSON
    Compatível com ambientes Roblox e Lua padrão
]]

local JSON = {}

-- Caracteres que precisam de escape em strings JSON
local ESCAPE_MAP = {
    ["\\"] = "\\\\",
    ['"'] = '\\"',
    ["\n"] = "\\n",
    ["\r"] = "\\r",
    ["\t"] = "\\t",
    ["\b"] = "\\b",
    ["\f"] = "\\f",
}

--- Escapa uma string para formato JSON
--- @param str string
--- @return string
local function escapeString(str)
    str = str:gsub('[\\"%c]', function(c)
        return ESCAPE_MAP[c] or string.format("\\u%04x", string.byte(c))
    end)
    return str
end

--- Verifica se uma tabela é um array (índices numéricos sequenciais)
--- @param tbl table
--- @return boolean
local function isArray(tbl)
    local count = 0
    for _ in pairs(tbl) do
        count = count + 1
    end
    for i = 1, count do
        if tbl[i] == nil then
            return false
        end
    end
    return count > 0
end

--- Codifica um valor Lua para JSON
--- @param value any O valor a ser codificado
--- @param indent number|nil Nível de indentação (nil para compacto)
--- @param currentIndent number Indentação atual
--- @return string
function JSON.encode(value, indent, currentIndent)
    indent = indent or nil
    currentIndent = currentIndent or 0

    local valueType = type(value)

    if value == nil then
        return "null"
    elseif valueType == "boolean" then
        return tostring(value)
    elseif valueType == "number" then
        if value ~= value then -- NaN
            return "null"
        elseif value == math.huge then
            return "null"
        elseif value == -math.huge then
            return "null"
        end
        return tostring(value)
    elseif valueType == "string" then
        return '"' .. escapeString(value) .. '"'
    elseif valueType == "table" then
        local parts = {}
        local newIndent = currentIndent + (indent or 0)
        local separator = indent and ",\n" or ","
        local padding = indent and string.rep(" ", newIndent) or ""
        local closePadding = indent and string.rep(" ", currentIndent) or ""
        local colon = indent and ": " or ":"

        if isArray(value) then
            for i = 1, #value do
                local encoded = JSON.encode(value[i], indent, newIndent)
                parts[#parts + 1] = padding .. encoded
            end
            if #parts == 0 then
                return "[]"
            end
            if indent then
                return "[\n" .. table.concat(parts, separator) .. "\n" .. closePadding .. "]"
            else
                -- Remove padding from parts for compact format
                local compactParts = {}
                for i = 1, #value do
                    compactParts[#compactParts + 1] = JSON.encode(value[i], indent, newIndent)
                end
                return "[" .. table.concat(compactParts, ",") .. "]"
            end
        else
            local keys = {}
            for k in pairs(value) do
                if type(k) == "string" or type(k) == "number" then
                    keys[#keys + 1] = k
                end
            end
            table.sort(keys, function(a, b)
                return tostring(a) < tostring(b)
            end)

            for _, k in ipairs(keys) do
                local keyStr = '"' .. escapeString(tostring(k)) .. '"'
                local encoded = JSON.encode(value[k], indent, newIndent)
                parts[#parts + 1] = padding .. keyStr .. colon .. encoded
            end
            if #parts == 0 then
                return "{}"
            end
            if indent then
                return "{\n" .. table.concat(parts, separator) .. "\n" .. closePadding .. "}"
            else
                local compactParts = {}
                for _, k in ipairs(keys) do
                    local keyStr = '"' .. escapeString(tostring(k)) .. '"'
                    local encoded = JSON.encode(value[k], indent, newIndent)
                    compactParts[#compactParts + 1] = keyStr .. ":" .. encoded
                end
                return "{" .. table.concat(compactParts, ",") .. "}"
            end
        end
    else
        return "null"
    end
end

--- Codifica um valor Lua para JSON formatado (pretty print)
--- @param value any O valor a ser codificado
--- @param indentSize number|nil Tamanho da indentação (padrão: 2)
--- @return string
function JSON.encodePretty(value, indentSize)
    return JSON.encode(value, indentSize or 2, 0)
end

--- Decodifica uma string JSON para valor Lua
--- @param str string A string JSON
--- @return any O valor decodificado
--- @return string|nil Mensagem de erro se houver falha
function JSON.decode(str)
    if type(str) ~= "string" then
        return nil, "Expected string, got " .. type(str)
    end

    local pos = 1

    local function skipWhitespace()
        pos = str:find("[^ \t\r\n]", pos) or (#str + 1)
    end

    local function peek()
        return str:sub(pos, pos)
    end

    local function consume(expected)
        if str:sub(pos, pos) ~= expected then
            return false
        end
        pos = pos + 1
        return true
    end

    local parseValue -- forward declaration

    local function parseString()
        if not consume('"') then
            return nil, "Expected '\"' at position " .. pos
        end
        local result = {}
        while pos <= #str do
            local c = str:sub(pos, pos)
            if c == '"' then
                pos = pos + 1
                return table.concat(result)
            elseif c == '\\' then
                pos = pos + 1
                local esc = str:sub(pos, pos)
                if esc == '"' then result[#result + 1] = '"'
                elseif esc == '\\' then result[#result + 1] = '\\'
                elseif esc == '/' then result[#result + 1] = '/'
                elseif esc == 'n' then result[#result + 1] = '\n'
                elseif esc == 'r' then result[#result + 1] = '\r'
                elseif esc == 't' then result[#result + 1] = '\t'
                elseif esc == 'b' then result[#result + 1] = '\b'
                elseif esc == 'f' then result[#result + 1] = '\f'
                elseif esc == 'u' then
                    local hex = str:sub(pos + 1, pos + 4)
                    local codepoint = tonumber(hex, 16)
                    if codepoint then
                        if codepoint < 128 then
                            result[#result + 1] = string.char(codepoint)
                        else
                            -- UTF-8 encoding simplificado
                            result[#result + 1] = string.char(
                                192 + math.floor(codepoint / 64),
                                128 + (codepoint % 64)
                            )
                        end
                        pos = pos + 4
                    end
                end
                pos = pos + 1
            else
                result[#result + 1] = c
                pos = pos + 1
            end
        end
        return nil, "Unterminated string"
    end

    local function parseNumber()
        local startPos = pos
        if str:sub(pos, pos) == '-' then pos = pos + 1 end
        while pos <= #str and str:sub(pos, pos):match("%d") do pos = pos + 1 end
        if pos <= #str and str:sub(pos, pos) == '.' then
            pos = pos + 1
            while pos <= #str and str:sub(pos, pos):match("%d") do pos = pos + 1 end
        end
        if pos <= #str and str:sub(pos, pos):match("[eE]") then
            pos = pos + 1
            if pos <= #str and str:sub(pos, pos):match("[%+%-]") then pos = pos + 1 end
            while pos <= #str and str:sub(pos, pos):match("%d") do pos = pos + 1 end
        end
        local numStr = str:sub(startPos, pos - 1)
        local num = tonumber(numStr)
        if not num then
            return nil, "Invalid number at position " .. startPos
        end
        return num
    end

    local function parseArray()
        if not consume('[') then
            return nil, "Expected '['"
        end
        local arr = {}
        skipWhitespace()
        if peek() == ']' then
            pos = pos + 1
            return arr
        end
        while true do
            skipWhitespace()
            local val, err = parseValue()
            if err then return nil, err end
            arr[#arr + 1] = val
            skipWhitespace()
            if not consume(',') then
                break
            end
        end
        if not consume(']') then
            return nil, "Expected ']' at position " .. pos
        end
        return arr
    end

    local function parseObject()
        if not consume('{') then
            return nil, "Expected '{'"
        end
        local obj = {}
        skipWhitespace()
        if peek() == '}' then
            pos = pos + 1
            return obj
        end
        while true do
            skipWhitespace()
            local key, err = parseString()
            if err then return nil, err end
            skipWhitespace()
            if not consume(':') then
                return nil, "Expected ':' at position " .. pos
            end
            skipWhitespace()
            local val
            val, err = parseValue()
            if err then return nil, err end
            obj[key] = val
            skipWhitespace()
            if not consume(',') then
                break
            end
        end
        if not consume('}') then
            return nil, "Expected '}' at position " .. pos
        end
        return obj
    end

    parseValue = function()
        skipWhitespace()
        local c = peek()
        if c == '"' then
            return parseString()
        elseif c == '{' then
            return parseObject()
        elseif c == '[' then
            return parseArray()
        elseif c == 't' then
            if str:sub(pos, pos + 3) == "true" then
                pos = pos + 4
                return true
            end
            return nil, "Invalid value at position " .. pos
        elseif c == 'f' then
            if str:sub(pos, pos + 4) == "false" then
                pos = pos + 5
                return false
            end
            return nil, "Invalid value at position " .. pos
        elseif c == 'n' then
            if str:sub(pos, pos + 3) == "null" then
                pos = pos + 4
                return nil
            end
            return nil, "Invalid value at position " .. pos
        elseif c == '-' or c:match("%d") then
            return parseNumber()
        else
            return nil, "Unexpected character '" .. c .. "' at position " .. pos
        end
    end

    local result, err = parseValue()
    if err then
        return nil, err
    end
    return result
end

return JSON
