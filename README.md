# 🔒 Scanning-Lua v2.0.0

> Scanner de Segurança Inteligente para Roblox — Análise contextual com Risk Score, detecção de ofuscação, monitoramento de rede avançado, anti-detecção e alertas Discord.

## 🚀 Uso Rápido (loadstring)

Cole no seu executor (Wave, Synapse, Fluxus, etc.):

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/oxomerketwere/Scanning-Lua/main/loader.lua"))()
```

### Desativar auto-scan (carregar sem escanear):
```lua
getgenv().ScanningLua_AUTO_SCAN = false
loadstring(game:HttpGet("https://raw.githubusercontent.com/oxomerketwere/Scanning-Lua/main/loader.lua"))()
```

## 🔥 O que há de novo na v2

| Feature | v1 | v2 |
|---------|----|----|
| Detecção | Pattern matching simples | **Risk Score contextual** com combinações perigosas |
| Ofuscação | Não detectava | **Detecta**: Luraph, Moonsec, IronBrew, Base64, hex encoding, minificação |
| Network | Whitelist básica | **Parser de URL completo**, domínios de risco catalogados, detecção de burst |
| Anti-detecção | Nenhuma | **Nomes randomizados**, delay aleatório, output bufferizado |
| Análise | Lista padrões | **Score numérico** + nível (LOW → CRITICAL) + combos multiplicadores |
| Discord | Não tinha | **Webhook com embeds** — alertas em tempo real |
| Fingerprint | Não tinha | **Detecta executor**, capabilities, avaliação de risco do ambiente |

## 🎯 Risk Score Engine (Análise Contextual)

Em vez de simplesmente listar padrões encontrados, o v2 calcula um **score de risco numérico** considerando:

### Pesos individuais
```
loadstring      → +8 pontos
hookfunction    → +9 pontos
HttpGet         → +4 pontos
getrawmetatable → +7 pontos
...
```

### Combinações perigosas (multiplicadores!)
```
loadstring + HttpGet      → score × 2.5  ("Remote Code Execution")
getrawmetatable + hookfn  → score × 2.0  ("Full Environment Hijack")
getnamecall + setnamecall → score × 1.8  ("Namecall Hijack")
debug.setupvalue + getfenv → score × 2.0 ("Upvalue + Env Manipulation")
```

### Bonus de ofuscação
```
Ofuscador conhecido (Luraph, etc.) → +15 pontos
Base64 payload                      → +8 pontos
Hex encoding                        → +6 pontos
```

### Nível final
| Score | Nível |
|-------|-------|
| 0 | NONE |
| 1-9 | LOW |
| 10-24 | MEDIUM |
| 25-49 | HIGH |
| 50+ | CRITICAL |

Exemplo real:
```
Script com HttpGet + loadstring:
  HttpGet = 4 pts + loadstring = 8 pts = 12
  Combo "Remote Code Execution" × 2.5 = 30
  → Nível: HIGH ✅
```

## 📁 Estrutura do Projeto

```
Scanning-Lua/
├── loader.lua                          # 🎯 Arquivo único para loadstring (TUDO AQUI)
├── main.lua                            # Ponto de entrada (Lua padrão / demo)
├── config.lua                          # Configurações globais
├── modules/
│   ├── json.lua                        # JSON encoder/decoder
│   ├── logger.lua                      # Logger com saída JSON
│   ├── filters.lua                     # Filtros com cache e whitelist
│   ├── scanner.lua                     # Scanner de instâncias (async)
│   ├── vulnerability_detector.lua      # Detector de vulnerabilidades
│   ├── network_monitor.lua             # Monitor de rede
│   ├── obfuscation_detector.lua        # 🆕 Detector de ofuscação
│   ├── environment_fingerprinter.lua   # 🆕 Fingerprint do executor
│   ├── anti_detection.lua              # 🆕 Anti-detecção
│   └── discord_webhook.lua             # 🆕 Webhook Discord
├── logs/                               # Logs gerados
└── reports/                            # Relatórios gerados
```

## 🛡️ Detecções

### Vulnerabilidades
| ID | Categoria | Severidade |
|----|-----------|-----------|
| `VULN-CI-001` | Code Injection (loadstring) | 🔴 CRITICAL |
| `VULN-MM-001` | Memory Manipulation (metatables) | 🔴 CRITICAL |
| `VULN-MM-002` | Hook de funções | 🔴 CRITICAL |
| `VULN-COMBO` | Combinações perigosas | 🔴 CRITICAL |
| `VULN-DE-001` | Data Exfiltration (HTTP) | 🟠 HIGH |
| `VULN-PE-001` | Privilege Escalation | 🟠 HIGH |
| `VULN-AB-001` | Auth Bypass (namecall) | 🟠 HIGH |
| `VULN-OB-001` | Código ofuscado | 🟠 HIGH |
| `VULN-RE-001` | Remote Abuse | 🟡 MEDIUM |
| `VULN-IV-001` | Input Validation | 🟡 MEDIUM |

### Ofuscação Detectada
| Técnica | Severidade |
|---------|-----------|
| Luraph / Moonsec / IronBrew / PSU | 🔴 CRITICAL |
| Base64 payload (>200 chars) | 🔴 CRITICAL |
| String concatenation evasion | 🟠 HIGH |
| Hex/Octal encoding (>10 seq) | 🟠 HIGH |
| string.char construction | 🟠 HIGH |
| Anti-decompile techniques | 🟠 HIGH |
| I/l variable obfuscation | 🟠 HIGH |
| Code minification | 🟡 MEDIUM |
| High entropy strings | 🟡 MEDIUM |

### Network — Domínios de Risco
| Domínio | Risco | Motivo |
|---------|-------|--------|
| `iplogger.org` / `grabify.link` | 9 | IP grabber |
| `ngrok.io` | 8 | Tunnel (C2) |
| `webhook.site` / `requestbin.com` | 7 | Exfiltração |
| `pastebin.com` / `hastebin.com` | 6-7 | Hosting de payloads |
| `raw.githubusercontent.com` | 5 | Raw script hosting |
| `discord.com` / `cdn.discordapp.com` | 4-5 | Webhook exfil |
| `roblox.com` / `rbxcdn.com` | 0 | ✅ Confiável |

## ⚙️ API Completa

```lua
-- SCAN
ScanningLua.fullScan()                -- Scan completo (auto-salva)
ScanningLua.scanCode(code, name)      -- Analisar string de código → risk score
ScanningLua.scanScript(instance)      -- Analisar instância de script

-- MONITOR
ScanningLua.monitorAllRemotes(cb)     -- Monitorar todos os RemoteEvents
ScanningLua.logHTTP(method, url)      -- Registrar requisição HTTP

-- CONFIGURAÇÃO
ScanningLua.setDiscordWebhook(url)    -- Ativar alertas Discord

-- RELATÓRIOS
ScanningLua.printSummary()            -- Resumo formatado no console
ScanningLua.getReport()               -- Relatório como tabela Lua
ScanningLua.getReportJSON()           -- Relatório como JSON string
ScanningLua.getStats()                -- Estatísticas gerais
ScanningLua.getEnvironment()          -- Fingerprint do executor

-- CONTROLE
ScanningLua.saveAll()                 -- Salvar em JSON
ScanningLua.reset()                   -- Limpar dados
ScanningLua.shutdown()                -- Encerrar e salvar
```

## 📡 Discord Webhook

Configure para receber alertas em tempo real:

```lua
ScanningLua.setDiscordWebhook("https://discord.com/api/webhooks/SEU_WEBHOOK_AQUI")
ScanningLua.fullScan()  -- Envia resumo automaticamente
```

## 🔧 Executando Localmente (Lua 5.1+)

```bash
cd Scanning-Lua
lua main.lua
```

## 📝 Licença

Projeto para fins educacionais e de pesquisa em segurança.