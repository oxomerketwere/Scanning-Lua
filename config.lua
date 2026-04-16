--[[
    Scanning-Lua - Configuration
    Scanner de segurança para Roblox
    Configurações globais do projeto
]]

local Config = {}

-- Versão do scanner
Config.VERSION = "1.0.0"
Config.NAME = "Scanning-Lua"

-- Diretórios de saída
Config.LOG_DIR = "logs"
Config.REPORT_DIR = "reports"

-- Configurações do Logger
Config.Logger = {
    -- Nível mínimo de log: "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"
    MIN_LEVEL = "DEBUG",
    -- Salvar logs em arquivo JSON
    SAVE_TO_FILE = true,
    -- Nome base do arquivo de log
    FILE_PREFIX = "scan_log",
    -- Máximo de entradas por arquivo de log
    MAX_ENTRIES_PER_FILE = 10000,
    -- Incluir timestamp em cada entrada
    INCLUDE_TIMESTAMP = true,
    -- Incluir stack trace em erros
    INCLUDE_STACKTRACE = true,
}

-- Configurações do Scanner
Config.Scanner = {
    -- Módulos de scan habilitados
    SCAN_REMOTE_EVENTS = true,
    SCAN_REMOTE_FUNCTIONS = true,
    SCAN_BINDABLE_EVENTS = true,
    SCAN_HTTP_REQUESTS = true,
    SCAN_LOADSTRING = true,
    SCAN_REQUIRE = true,
    SCAN_DATASTORE = true,
    SCAN_MARKETPLACE = true,
    -- Intervalo entre scans automáticos (segundos)
    AUTO_SCAN_INTERVAL = 30,
    -- Habilitar scan automático
    AUTO_SCAN_ENABLED = false,
    -- Profundidade máxima de busca na árvore de instâncias
    MAX_DEPTH = 50,
}

-- Configurações de Filtros
Config.Filters = {
    -- Padrões suspeitos conhecidos
    SUSPICIOUS_PATTERNS = {
        "loadstring",
        "HttpGet",
        "HttpPost",
        "GetObjects",
        "require%((%d+)%)",
        "game:GetService%(\"HttpService\"%)",
        "syn%.request",
        "http_request",
        "request",
        "getrawmetatable",
        "setrawmetatable",
        "hookfunction",
        "hookmetamethod",
        "newcclosure",
        "getnamecallmethod",
        "setnamecallmethod",
        "getgenv",
        "getrenv",
        "getfenv",
        "setfenv",
        "debug%.getupvalue",
        "debug%.setupvalue",
        "debug%.getinfo",
        "debug%.getconstant",
        "debug%.setconstant",
        "firesignal",
        "fireserver",
        "fireclickdetector",
        "firetouchinterest",
        "fireproximityprompt",
    },
    -- Serviços que devem ser monitorados
    MONITORED_SERVICES = {
        "ReplicatedStorage",
        "ServerScriptService",
        "ServerStorage",
        "Workspace",
        "Players",
        "Lighting",
        "StarterGui",
        "StarterPack",
        "StarterPlayer",
    },
    -- Nomes de RemoteEvents suspeitos (padrões comuns em exploits)
    SUSPICIOUS_REMOTE_NAMES = {
        ".*Event.*",
        ".*Remote.*",
        ".*Fire.*",
        ".*Send.*",
        ".*Invoke.*",
        ".*Handler.*",
        ".*Callback.*",
    },
    -- Filtrar por severidade mínima: "LOW", "MEDIUM", "HIGH", "CRITICAL"
    MIN_SEVERITY = "LOW",
}

-- Configurações de Vulnerabilidades
Config.Vulnerability = {
    -- Categorias de vulnerabilidade
    CATEGORIES = {
        "REMOTE_ABUSE",
        "CODE_INJECTION",
        "DATA_EXFILTRATION",
        "PRIVILEGE_ESCALATION",
        "MEMORY_MANIPULATION",
        "NETWORK_EXPLOIT",
        "AUTHENTICATION_BYPASS",
        "INPUT_VALIDATION",
    },
    -- Gerar relatório automático ao finalizar scan
    AUTO_REPORT = true,
    -- Formato do relatório
    REPORT_FORMAT = "json",
}

-- Configurações do Monitor de Rede
Config.Network = {
    -- Monitorar requisições HTTP
    MONITOR_HTTP = true,
    -- Monitorar WebSocket
    MONITOR_WEBSOCKET = true,
    -- Domínios permitidos (whitelist)
    ALLOWED_DOMAINS = {
        "roblox.com",
        "rbxcdn.com",
        "robloxcdn.com",
    },
    -- Registrar todas as requisições (não apenas suspeitas)
    LOG_ALL_REQUESTS = false,
}

return Config
