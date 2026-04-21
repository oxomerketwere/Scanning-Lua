--[[
    Scanning-Lua - Table Validator Module
    Validação e saneamento de tabelas de configuração/detecção.
]]

local TableValidator = {}

local function isNonEmptyString(v)
    return type(v) == "string" and v ~= ""
end

local function isNumber(v)
    return type(v) == "number"
end

local function isArray(v)
    if type(v) ~= "table" then return false end
    local n = #v
    for i = 1, n do
        if v[i] == nil then
            return false
        end
    end
    return true
end

local function copyTable(t)
    local out = {}
    for k, v in pairs(t) do
        out[k] = v
    end
    return out
end

--- Valida e saneia uma lista de entries.
--- schema: {
---   required = {"field"...},
---   types = { field = "string"|"number"|"array" },
---   allowed = { field = { VALUE=true } },
---   defaults = { field = value }
--- }
function TableValidator.sanitizeArray(name, entries, schema, logger)
    if type(entries) ~= "table" then
        if logger then
            logger:warn("TABLE_VALIDATOR", string.format("%s inválida: esperado table, recebido %s. Usando lista vazia.", name, type(entries)))
        end
        return {}
    end

    local required = schema.required or {}
    local types = schema.types or {}
    local allowed = schema.allowed or {}
    local defaults = schema.defaults or {}

    local sanitized = {}
    local dropped = 0

    for idx, entry in ipairs(entries) do
        if type(entry) ~= "table" then
            dropped = dropped + 1
            if logger then
                logger:warn("TABLE_VALIDATOR", string.format("%s[%d] ignorada: entry não é table", name, idx))
            end
        else
            local item = copyTable(entry)

            for key, value in pairs(defaults) do
                if item[key] == nil then
                    item[key] = value
                end
            end

            local valid = true

            for _, key in ipairs(required) do
                if item[key] == nil then
                    valid = false
                    if logger then
                        logger:warn("TABLE_VALIDATOR", string.format("%s[%d] inválida: campo obrigatório ausente '%s'", name, idx, key))
                    end
                    break
                end
            end

            if valid then
                for key, expectedType in pairs(types) do
                    local value = item[key]
                    if value ~= nil then
                        if expectedType == "string" and not isNonEmptyString(value) then
                            valid = false
                        elseif expectedType == "number" and not isNumber(value) then
                            valid = false
                        elseif expectedType == "array" and not isArray(value) then
                            valid = false
                        end

                        if not valid then
                            if logger then
                                logger:warn("TABLE_VALIDATOR", string.format(
                                    "%s[%d] inválida: campo '%s' com tipo/valor inválido", name, idx, key
                                ))
                            end
                            break
                        end
                    end
                end
            end

            if valid then
                for key, allowedValues in pairs(allowed) do
                    local value = item[key]
                    if value ~= nil and type(allowedValues) == "table" and not allowedValues[value] then
                        valid = false
                        if logger then
                            logger:warn("TABLE_VALIDATOR", string.format(
                                "%s[%d] inválida: valor '%s' não permitido para '%s'", name, idx, tostring(value), key
                            ))
                        end
                        break
                    end
                end
            end

            if valid then
                sanitized[#sanitized + 1] = item
            else
                dropped = dropped + 1
            end
        end
    end

    if logger and dropped > 0 then
        logger:warn("TABLE_VALIDATOR", string.format(
            "%s: %d entradas inválidas removidas (restantes: %d)",
            name, dropped, #sanitized
        ))
    end

    return sanitized
end

return TableValidator
