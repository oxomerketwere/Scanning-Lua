--[[
    Scanning-Lua - Configuration
    Scanner de segurança para Roblox
    Configurações globais do projeto
]]

local Config = {}

-- Versão do scanner
Config.VERSION = "3.0.0"
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

-- Configurações do Behavior Analyzer (#11)
Config.Behavior = {
    -- Máximo de RemoteEvents criados antes de alertar
    MAX_REMOTE_CREATIONS = 10,
    -- Máximo de chamadas FireServer por minuto
    MAX_FIRE_SERVER_PER_MINUTE = 30,
    -- Máximo de GUIs invisíveis
    MAX_INVISIBLE_GUIS = 3,
    -- Máximo de instâncias criadas em burst
    MAX_INSTANCE_BURST = 50,
    -- Janela de burst (segundos)
    BURST_WINDOW_SECONDS = 5,
}

-- Configurações do Deobfuscator (#12)
Config.Deobfuscator = {
    -- Habilitar deobfuscação automática
    ENABLED = true,
    -- Resolver hex escapes
    RESOLVE_HEX = true,
    -- Resolver string.char
    RESOLVE_STRING_CHAR = true,
    -- Juntar strings concatenadas
    JOIN_STRINGS = true,
    -- Detectar base64
    DETECT_BASE64 = true,
}

-- Configurações do Signature System (#13)
Config.Signatures = {
    -- Assinaturas customizadas adicionais
    CUSTOM_SIGNATURES = {
        -- Exemplo:
        -- { name="Custom Backdoor", pattern="my_backdoor_pattern", severity="CRITICAL" },
    },
}

-- Configurações do Heuristic Engine (#14 + #22)
Config.Heuristic = {
    -- Pesos customizados (sobrescreve os padrão)
    CUSTOM_WEIGHTS = {
        -- Exemplo:
        -- loadstring = 10,
    },
}

-- Configurações do Incremental Scanner (#15)
Config.Incremental = {
    -- Habilitar scanner incremental
    ENABLED = true,
}

-- Configurações do Thread Controller (#16)
Config.ThreadControl = {
    -- Máximo de tasks simultâneas
    MAX_CONCURRENT_TASKS = 3,
    -- Yield a cada N operações
    YIELD_INTERVAL = 10,
    -- Duração do yield (segundos)
    YIELD_DURATION = 0.03,
    -- Tamanho do lote de processamento
    BATCH_SIZE = 20,
}

-- Configurações do Stealth Mode (#19)
Config.Stealth = {
    -- Habilitar modo stealth
    ENABLED = false,
    -- Buffer output em vez de imprimir diretamente
    BUFFER_OUTPUT = false,
    -- Flush buffer para console ao final
    FLUSH_TO_CONSOLE = true,
}

-- Configurações do Debug System (#20)
Config.Debug = {
    -- Modo verbose
    VERBOSE_MODE = false,
    -- Máximo de eventos no log
    MAX_EVENTS = 1000,
}

-- Configurações do Continuous Monitor (#24)
Config.ContinuousMonitor = {
    -- Intervalo entre ciclos de verificação (segundos)
    SCAN_INTERVAL = 30,
    -- Habilitar monitoramento contínuo
    ENABLED = false,
}

-- Configurações do False Positive Reducer (#26)
Config.FalsePositive = {
    -- Score mínimo para gerar alerta
    MIN_SCORE_TO_ALERT = 10,
    -- Severidade mínima para gerar alerta
    MIN_SEVERITY_TO_ALERT = "MEDIUM",
    -- Scripts na whitelist (ignorados pelo scanner)
    WHITELISTED_SCRIPTS = {},
    -- Padrões na whitelist
    WHITELISTED_PATTERNS = {},
    -- Domínios confiáveis
    WHITELISTED_DOMAINS = {
        "roblox.com",
        "rbxcdn.com",
        "robloxcdn.com",
    },
}

return Config
