--[[
    Scanning-Lua - Signature System Module (#13)
    Sistema de assinaturas tipo antivírus

    Banco de "ameaças conhecidas" com:
    - Nome da ameaça
    - Padrão de detecção
    - Severidade
    - Descrição
    - Hash de scripts maliciosos conhecidos

    Detecta scripts específicos conhecidos com alta precisão
]]

local SignatureSystem = {}
SignatureSystem.__index = SignatureSystem

--- Banco de assinaturas de ameaças conhecidas
local DEFAULT_SIGNATURES = {
    -- Backdoors conhecidos
    {
        id = "SIG-BD-001",
        name = "DarkDex Backdoor",
        category = "BACKDOOR",
        severity = "CRITICAL",
        pattern = "require%(%d+%)",
        description = "Require com ID numérico - técnica comum de backdoor para carregar módulos maliciosos.",
    },
    {
        id = "SIG-BD-002",
        name = "Infinite Yield Backdoor",
        category = "BACKDOOR",
        severity = "CRITICAL",
        pattern = "InfiniteYield",
        description = "Referência a script de administração não autorizado Infinite Yield.",
    },
    {
        id = "SIG-BD-003",
        name = "Hydroxide Backdoor",
        category = "BACKDOOR",
        severity = "CRITICAL",
        pattern = "Hydroxide",
        description = "Referência ao framework de exploit Hydroxide.",
    },
    {
        id = "SIG-BD-004",
        name = "Dex Explorer Backdoor",
        category = "BACKDOOR",
        severity = "HIGH",
        pattern = "Dex%s*Explorer",
        description = "Referência ao Dex Explorer - ferramenta de visualização de instâncias.",
    },

    -- Remote Spies
    {
        id = "SIG-RS-001",
        name = "Remote Spy (FireServer pattern)",
        category = "REMOTE_SPY",
        severity = "HIGH",
        pattern = "OnClientEvent.*FireServer",
        description = "Padrão de interceptação e replay de RemoteEvents.",
    },
    {
        id = "SIG-RS-002",
        name = "SimpleSpy",
        category = "REMOTE_SPY",
        severity = "HIGH",
        pattern = "SimpleSpy",
        description = "Referência ao SimpleSpy remote spy.",
    },
    {
        id = "SIG-RS-003",
        name = "Remote Spy via Namecall",
        category = "REMOTE_SPY",
        severity = "HIGH",
        pattern = "getnamecallmethod.*FireServer",
        description = "Interceptação de remotes via hooking de __namecall.",
    },

    -- Data Exfiltration
    {
        id = "SIG-DE-001",
        name = "Webhook Data Stealer",
        category = "DATA_EXFILTRATION",
        severity = "CRITICAL",
        pattern = "discord%.com/api/webhooks",
        description = "Envio de dados para Discord webhook - possível exfiltração.",
    },
    {
        id = "SIG-DE-002",
        name = "Pastebin Payload Loader",
        category = "DATA_EXFILTRATION",
        severity = "HIGH",
        pattern = "pastebin%.com/raw/",
        description = "Carregamento de payload de Pastebin.",
    },
    {
        id = "SIG-DE-003",
        name = "GitHub Raw Script Loader",
        category = "CODE_INJECTION",
        severity = "HIGH",
        pattern = "raw%.githubusercontent%.com.*%.lua",
        description = "Carregamento de script Lua de repositório GitHub.",
    },

    -- Code Injection
    {
        id = "SIG-CI-001",
        name = "Remote Code Execution",
        category = "CODE_INJECTION",
        severity = "CRITICAL",
        pattern = "loadstring.*HttpGet",
        description = "Execução de código remoto via loadstring + HttpGet.",
    },
    {
        id = "SIG-CI-002",
        name = "Encoded Payload Execution",
        category = "CODE_INJECTION",
        severity = "CRITICAL",
        pattern = "loadstring.*base64",
        description = "Execução de payload codificado em base64.",
    },
    {
        id = "SIG-CI-003",
        name = "Dynamic Require Injection",
        category = "CODE_INJECTION",
        severity = "HIGH",
        pattern = "require%(tonumber",
        description = "Require com ID convertido dinamicamente - possível injeção.",
    },

    -- Environment Manipulation
    {
        id = "SIG-EM-001",
        name = "Environment Hijack",
        category = "ENVIRONMENT_MANIPULATION",
        severity = "CRITICAL",
        pattern = "getrawmetatable.*__namecall",
        description = "Manipulação de metatable do game para interceptar chamadas.",
    },
    {
        id = "SIG-EM-002",
        name = "Global Environment Pollution",
        category = "ENVIRONMENT_MANIPULATION",
        severity = "HIGH",
        pattern = "getgenv%(%)[\"']",
        description = "Escrita direta no ambiente global compartilhado.",
    },

    -- Anti-detection by malware
    {
        id = "SIG-AD-001",
        name = "Scanner Evasion (pcall wrap)",
        category = "EVASION",
        severity = "MEDIUM",
        pattern = "pcall.*hookfunction",
        description = "Uso de pcall para proteger hookfunction contra erros/detecção.",
    },
    {
        id = "SIG-AD-002",
        name = "Anti-Kick Protection",
        category = "EVASION",
        severity = "HIGH",
        pattern = "hookmetamethod.*Kick",
        description = "Hook em método Kick para prevenir remoção do jogador.",
    },

    -- Known malicious patterns
    {
        id = "SIG-MP-001",
        name = "Synapse Request to External",
        category = "NETWORK_ABUSE",
        severity = "HIGH",
        pattern = "syn%.request.*Url.*Method.*POST",
        description = "Requisição POST via syn.request para servidor externo.",
    },
    {
        id = "SIG-MP-002",
        name = "IP Logger Pattern",
        category = "DATA_EXFILTRATION",
        severity = "CRITICAL",
        pattern = "iplogger%.org",
        description = "Referência a serviço de IP logging - tentativa de rastrear IPs.",
    },
    {
        id = "SIG-MP-003",
        name = "Grabify Link",
        category = "DATA_EXFILTRATION",
        severity = "CRITICAL",
        pattern = "grabify%.link",
        description = "Referência a serviço Grabify - tentativa de rastrear IPs.",
    },
}

--- Cria uma nova instância do sistema de assinaturas
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table SignatureSystem instance
function SignatureSystem.new(config, logger)
    local self = setmetatable({}, SignatureSystem)
    self.config = config or {}
    self.logger = logger
    self.signatures = {}
    self.customSignatures = {}
    self.detections = {}
    self.stats = {
        total_scanned = 0,
        total_detections = 0,
        by_category = {},
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
    }

    -- Carregar assinaturas padrão
    for _, sig in ipairs(DEFAULT_SIGNATURES) do
        self.signatures[#self.signatures + 1] = sig
    end

    -- Carregar assinaturas customizadas do config
    if config.CUSTOM_SIGNATURES then
        for _, sig in ipairs(config.CUSTOM_SIGNATURES) do
            self:addSignature(sig)
        end
    end

    return self
end

--- Adiciona uma nova assinatura ao banco
--- @param signature table Assinatura { id, name, category, severity, pattern, description }
function SignatureSystem:addSignature(signature)
    if not signature.pattern then return end

    local sig = {
        id = signature.id or ("SIG-CUSTOM-" .. (#self.customSignatures + 1)),
        name = signature.name or "Custom Signature",
        category = signature.category or "CUSTOM",
        severity = signature.severity or "MEDIUM",
        pattern = signature.pattern,
        description = signature.description or "Assinatura customizada",
    }

    self.signatures[#self.signatures + 1] = sig
    self.customSignatures[#self.customSignatures + 1] = sig
end

--- Escaneia código contra todas as assinaturas
--- @param code string Código a escanear
--- @param source string Origem do código
--- @return table Lista de detecções
function SignatureSystem:scan(code, source)
    if type(code) ~= "string" then return {} end

    self.stats.total_scanned = self.stats.total_scanned + 1
    source = source or "unknown"
    local detections = {}

    for _, sig in ipairs(self.signatures) do
        local matchStart, matchEnd = code:find(sig.pattern)
        if matchStart then
            local matchedText = code:sub(matchStart, math.min(matchEnd, matchStart + 100))

            -- Extrair número da linha
            local lineNum = 1
            for _ in code:sub(1, matchStart):gmatch("\n") do
                lineNum = lineNum + 1
            end

            local detection = {
                signature_id = sig.id,
                signature_name = sig.name,
                category = sig.category,
                severity = sig.severity,
                description = sig.description,
                matched_text = matchedText,
                source = source,
                line_number = lineNum,
                timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            }

            detections[#detections + 1] = detection
            self.detections[#self.detections + 1] = detection
            self.stats.total_detections = self.stats.total_detections + 1
            self.stats.by_category[sig.category] = (self.stats.by_category[sig.category] or 0) + 1
            self.stats.by_severity[sig.severity] = (self.stats.by_severity[sig.severity] or 0) + 1

            if self.logger then
                self.logger:warn("SIGNATURE", string.format(
                    "[%s] %s detectado em %s (linha %d) - %s",
                    sig.id, sig.name, source, lineNum, sig.severity
                ), detection)
            end
        end
    end

    return detections
end

--- Calcula hash simples de um script (para detecção por hash)
--- @param code string Código do script
--- @return string Hash simplificado
function SignatureSystem.computeHash(code)
    if type(code) ~= "string" then return "nil" end

    -- Hash DJB2 simplificado
    local hash = 5381
    for i = 1, #code do
        hash = ((hash * 33) + code:byte(i)) % 2147483647
    end
    return string.format("%08x", hash)
end

--- Retorna todas as detecções
--- @return table
function SignatureSystem:getDetections()
    return self.detections
end

--- Retorna número total de assinaturas
--- @return number
function SignatureSystem:getSignatureCount()
    return #self.signatures
end

--- Retorna estatísticas
--- @return table
function SignatureSystem:getStats()
    return self.stats
end

--- Limpa detecções
function SignatureSystem:reset()
    self.detections = {}
    self.stats = {
        total_scanned = 0,
        total_detections = 0,
        by_category = {},
        by_severity = { LOW = 0, MEDIUM = 0, HIGH = 0, CRITICAL = 0 },
    }
end

return SignatureSystem
