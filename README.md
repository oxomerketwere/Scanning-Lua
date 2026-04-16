# 🔒 Scanning-Lua v3.0.0

> Scanner de Segurança Avançado para Roblox — Análise de comportamento runtime, deobfuscação, sistema de assinaturas, heurística com scoring, scanner incremental, correlação entre scripts, monitoramento contínuo e muito mais.

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

## 🔥 O que há de novo na v3

| Feature | v2 | v3 |
|---------|----|----|
| Detecção | Risk Score contextual | **Heurística avançada** com pesos, combos e ajuste contextual |
| Ofuscação | Detecção | **Deobfuscação ativa**: junta strings, resolve base64, string.char, hex |
| Assinaturas | Não tinha | **Banco de ameaças** com 20+ assinaturas (tipo antivírus) |
| Comportamento | Estático | **Análise runtime**: hooks em Instance.new, FireServer, GUI tracking |
| Performance | Scan completo sempre | **Scanner incremental** com hash caching (pula scripts inalterados) |
| Threads | Sem controle | **Thread controller** com fila de prioridade e yield automático |
| Hooks | Não detectava | **Detector de hooks maliciosos** e verificação de metatables |
| Integridade | Sem proteção | **Anti-sabotagem** com auto-recovery de módulos comprometidos |
| Stealth | Nomes randomizados | **Modo invisível completo**: esconde instâncias, buffering de output |
| Debug | Logs básicos | **Sistema de debug** com timers, replay de eventos, métricas |
| Dashboard | Não tinha | **Dashboard console** com barras de risco e visualização |
| Correlação | Não tinha | **Detecta ecossistemas** de scripts maliciosos coordenados |
| Monitoramento | Scan único | **Loop contínuo** com detecção de scripts novos em tempo real |
| Payloads | Básico | **Detector avançado** captura URLs, classifica risco, segue cadeias |
| Falso Positivo | Sem controle | **Whitelist + contexto + score mínimo** reduz alertas inúteis |

## 🧠 Módulos Avançados (v3)

### #11 — Análise de Comportamento Runtime
Observa o que o script **FAZ** em runtime (não só o código estático):
- Hook em `Instance.new` para monitorar criação de instâncias
- Interceptação de `FireServer`/`InvokeServer` via namecall
- Detecção de GUIs invisíveis (possível backdoor)
- Alerta para criação excessiva de RemoteEvents

### #12 — Deobfuscação Básica
Tenta **reverter parcialmente** ofuscação:
- Junta strings concatenadas: `"ab".."cd"` → `"abcd"`
- Resolve `string.char(72,101,108,108,111)` → `"Hello"`
- Decodifica strings base64
- Resolve hex/octal escapes
- Identifica junk code (variáveis mortas, dead code)

### #13 — Sistema de Assinaturas
Banco de **20+ ameaças conhecidas** com detecção por padrão:
- `SIG-BD-*` — Backdoors (DarkDex, Infinite Yield, Hydroxide)
- `SIG-RS-*` — Remote Spies (SimpleSpy, namecall hooks)
- `SIG-DE-*` — Data Exfiltration (webhooks, pastebin, IP loggers)
- `SIG-CI-*` — Code Injection (loadstring+HttpGet, encoded payloads)
- `SIG-EM-*` — Environment Manipulation (metatable hijack)
- Suporte a assinaturas customizadas

### #14 + #22 — Heurística Avançada com Scoring
Motor de pontuação com **pesos configuráveis** e **multiplicadores**:
```
Score = Σ(indicador × peso × min(contagem, 3)) × melhor_multiplicador + ajuste_contexto
```

Ajustes de contexto:
- Script pequeno + indicadores → **+5 pontos** (mais suspeito)
- Script grande + comentado + organizado → **-10 pontos** (menos suspeito)
- Script mínimo com loadstring+HttpGet → **+10 pontos** (loader clássico)

### #15 — Scanner Incremental
**Hash caching** para ganho enorme de performance:
- Calcula hash DJB2 de cada script
- Só reanalisar se o hash mudou
- Cache hit rate monitorado
- Perfeito para scans repetidos em jogos grandes

### #16 — Thread Controller
Evita **travar o jogo** em scans pesados:
- Fila de tarefas com prioridade
- Limite de tasks simultâneas configurável
- Yield automático entre operações
- Processamento em lote (batch) com callbacks

### #17 — Detector de Hooks Maliciosos
Detecta se outros scripts **hookaram funções críticas**:
- Captura baseline de funções originais no startup
- Verifica se referências ou closure types mudaram
- Monitora metatables do `game`
- Detecta `hookfunction`, `getrawmetatable`, `replaceclosure`

### #18 — Proteção Anti-Sabotagem
Protege o scanner contra **ataques direcionados**:
- Registro de integridade de módulos e funções
- Verificação periódica de alterações
- Auto-recovery: restaura funções alteradas
- Alertas de violação de integridade

### #19 — Modo Stealth
Operação **completamente invisível**:
- Instâncias escondidas do explorer (via `gethui`)
- Nomes randomizados para evitar fingerprinting
- Output bufferizado (nada no console durante scan)
- Criação de instâncias stealth com nomes aleatórios

### #20 — Sistema de Debug
Ferramentas de **diagnóstico profissional**:
- Modo verbose com stack traces
- Timers de performance com métricas min/max/avg
- Log de eventos com replay filtrado
- Medição automática de operações

### #21 — Dashboard
**Visualização completa** dos resultados:
- Dashboard formatado no console com box drawing
- Barra de risco visual (🟢🟡🟠🔴⚫)
- Geração de embeds para Discord webhook
- Seções para cada módulo (scanner, vulns, heuristic, network, etc.)

### #23 — Correlação entre Scripts
Detecta **ecossistemas maliciosos** de scripts coordenados:
- Comunicação via variáveis globais (`_G`, `shared`, `getgenv`)
- URLs HTTP compartilhadas
- Cadeias downloader → executor
- Detecção de componentes conectados (BFS)

### #24 — Monitoramento Contínuo
**Loop leve** que detecta mudanças em tempo real:
- `DescendantAdded` em serviços principais
- Auto-scan de novos scripts
- Detecção de remoção de scripts
- Rate-limited para não impactar performance

### #25 — Detecção de Payload Remoto
Analisa o padrão `loadstring(game:HttpGet(...))()`:
- Captura todas as URLs do código
- Classificação de risco por domínio
- Seguimento de cadeias de payloads (depth limit: 3)
- Download e análise recursiva de conteúdo

### #26 — Redução de Falsos Positivos
Sem isso, o scanner vira inútil:
- **Whitelist** de scripts/padrões/domínios
- **Score mínimo** para gerar alerta
- **Severidade mínima** configurável
- **Regras de contexto**: código documentado reduz score, loader mínimo aumenta

## 🎯 Risk Score Engine

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
loadstring + HttpGet        → score × 2.5  ("Remote Code Execution")
loadstring + obfuscador     → score × 3.0  ("Obfuscated Remote Execution")
getrawmetatable + hookfn    → score × 2.0  ("Full Environment Hijack")
debug.setupvalue + getfenv  → score × 2.0  ("Upvalue + Env Manipulation")
```

### Nível final
| Score | Nível | Emoji |
|-------|-------|-------|
| 0 | NONE | 🟢 |
| 1-9 | LOW | 🟡 |
| 10-24 | MEDIUM | 🟠 |
| 25-49 | HIGH | 🔴 |
| 50+ | CRITICAL | ⚫ |

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
│   ├── obfuscation_detector.lua        # Detector de ofuscação
│   ├── environment_fingerprinter.lua   # Fingerprint do executor
│   ├── anti_detection.lua              # Anti-detecção
│   ├── discord_webhook.lua             # Webhook Discord
│   ├── behavior_analyzer.lua           # 🆕 Análise de comportamento runtime (#11)
│   ├── deobfuscator.lua                # 🆕 Deobfuscação básica (#12)
│   ├── signature_system.lua            # 🆕 Sistema de assinaturas (#13)
│   ├── heuristic_engine.lua            # 🆕 Heurística avançada + scoring (#14/#22)
│   ├── incremental_scanner.lua         # 🆕 Scanner incremental com cache (#15)
│   ├── thread_controller.lua           # 🆕 Controle de threads (#16)
│   ├── hook_detector.lua               # 🆕 Detector de hooks maliciosos (#17)
│   ├── integrity_guard.lua             # 🆕 Proteção anti-sabotagem (#18)
│   ├── stealth_mode.lua                # 🆕 Modo stealth (#19)
│   ├── debug_system.lua                # 🆕 Sistema de debug (#20)
│   ├── dashboard.lua                   # 🆕 Dashboard console/webhook (#21)
│   ├── script_correlator.lua           # 🆕 Correlação entre scripts (#23)
│   ├── continuous_monitor.lua          # 🆕 Monitoramento contínuo (#24)
│   ├── payload_detector.lua            # 🆕 Detecção de payload remoto (#25)
│   └── false_positive_reducer.lua      # 🆕 Redução de falsos positivos (#26)
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
-- SCAN BÁSICO
ScanningLua.fullScan()                -- Scan completo com todos os módulos (auto-salva)
ScanningLua.scanCode(code, name)      -- Analisar string de código → resultado completo

-- MONITORAMENTO
ScanningLua.logHTTPRequest(method, url, headers, body)  -- Registrar requisição HTTP
ScanningLua.startContinuousMonitoring(callback)          -- Monitoramento em tempo real
ScanningLua.stopContinuousMonitoring()                   -- Parar monitoramento

-- STEALTH & DEBUG
ScanningLua.enableStealth()           -- Ativar modo invisível
ScanningLua.disableStealth()          -- Desativar modo invisível
ScanningLua.setVerbose(true/false)    -- Modo verbose para debug

-- DASHBOARD & RELATÓRIOS
ScanningLua.showDashboard()           -- Exibir dashboard no console
ScanningLua.getDashboardEmbed()       -- Gerar embed para Discord webhook
ScanningLua.getStats()                -- Estatísticas de todos os módulos
ScanningLua.getVulnerabilityReport()  -- Relatório de vulnerabilidades

-- ANÁLISE AVANÇADA
ScanningLua.getSignatureDetections()  -- Ver detecções de assinatura
ScanningLua.getHeuristicAnalyses()    -- Ver análises heurísticas
ScanningLua.getCorrelationReport()    -- Ver correlações entre scripts
ScanningLua.addSignature(sig)         -- Adicionar assinatura customizada
ScanningLua.whitelistScript(path)     -- Adicionar script à whitelist

-- INTEGRIDADE & SEGURANÇA
ScanningLua.checkIntegrity()          -- Verificar integridade dos módulos
ScanningLua.autoRecover()             -- Recuperar módulos comprometidos

-- DEBUG AVANÇADO
ScanningLua.replayEvents(filter)      -- Replay de eventos de debug

-- CONTROLE
ScanningLua.saveAllResults()          -- Salvar em JSON
ScanningLua.reset()                   -- Limpar todos os dados
ScanningLua.shutdown()                -- Encerrar e salvar tudo
```

## 📡 Discord Webhook

Configure para receber alertas em tempo real:

```lua
ScanningLua.setDiscordWebhook("https://discord.com/api/webhooks/SEU_WEBHOOK_AQUI")
ScanningLua.fullScan()  -- Envia resumo automaticamente
```

Ou gere o embed manualmente:
```lua
local embed = ScanningLua.getDashboardEmbed()
-- Use com discord_webhook module
```

## ⚙️ Configuração

Todas as configurações estão em `config.lua`:

```lua
-- Heurística
Config.Heuristic.CUSTOM_WEIGHTS = { loadstring = 10 }

-- Falsos Positivos
Config.FalsePositive.MIN_SCORE_TO_ALERT = 10
Config.FalsePositive.MIN_SEVERITY_TO_ALERT = "MEDIUM"
Config.FalsePositive.WHITELISTED_SCRIPTS = { "meu_script_seguro.lua" }

-- Performance
Config.Incremental.ENABLED = true
Config.ThreadControl.MAX_CONCURRENT_TASKS = 3
Config.ThreadControl.BATCH_SIZE = 20

-- Comportamento
Config.Behavior.MAX_REMOTE_CREATIONS = 10
Config.Behavior.MAX_FIRE_SERVER_PER_MINUTE = 30

-- Stealth
Config.Stealth.ENABLED = false
Config.Stealth.BUFFER_OUTPUT = false

-- Debug
Config.Debug.VERBOSE_MODE = false

-- Monitoramento Contínuo
Config.ContinuousMonitor.SCAN_INTERVAL = 30
Config.ContinuousMonitor.ENABLED = false
```

## 🔧 Executando Localmente (Lua 5.1+)

```bash
cd Scanning-Lua
lua main.lua
```

A demo mostra:
- Análise de 7 amostras de código (malicioso, seguro, ofuscado, cadeia)
- Detecção de correlações entre scripts
- Scanner incremental com cache
- Dashboard completo com todas as métricas
- Performance timing de cada operação

## 📝 Licença

Projeto para fins educacionais e de pesquisa em segurança.