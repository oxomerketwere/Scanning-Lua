# 🔒 Scanning-Lua

> Scanner de Segurança para Roblox — Detecta vulnerabilidades, monitora RemoteEvents, analisa scripts e registra atividade de rede. Logs em JSON.

## 🚀 Uso Rápido (loadstring)

Cole no seu executor (Wave, Synapse, Fluxus, etc.):

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/oxomerketwere/Scanning-Lua/main/loader.lua"))()
```

O scanner executa automaticamente ao carregar. Depois, use a API via console:

```lua
-- Scan completo do jogo
ScanningLua.fullScan()

-- Analisar código Lua específico
ScanningLua.scanCode("loadstring(game:HttpGet('...'))()", "meu_script.lua")

-- Analisar um script do jogo
ScanningLua.scanScript(game.Workspace.SomeScript)

-- Monitorar todos os RemoteEvents em tempo real
ScanningLua.monitorAllRemotes(function(data)
    print("Remote:", data.remote_name, "Args:", data.arg_count)
end)

-- Ver resumo no console
ScanningLua.printSummary()

-- Salvar relatórios em JSON (pasta ScanningLua/)
ScanningLua.saveAllResults()

-- Ver relatório de vulnerabilidades
print(ScanningLua.getVulnerabilityReportJSON())

-- Encerrar e salvar tudo
ScanningLua.shutdown()
```

## 📁 Estrutura do Projeto

```
Scanning-Lua/
├── loader.lua                          # 🎯 Arquivo único para loadstring
├── main.lua                            # Ponto de entrada (Lua padrão)
├── config.lua                          # Configurações globais
├── modules/
│   ├── json.lua                        # Serialização/deserialização JSON
│   ├── logger.lua                      # Sistema de logs com saída JSON
│   ├── filters.lua                     # Filtros e detecção de padrões suspeitos
│   ├── scanner.lua                     # Scanner de instâncias e scripts
│   ├── vulnerability_detector.lua      # Detector e classificador de vulnerabilidades
│   └── network_monitor.lua             # Monitor de atividade de rede
├── logs/                               # Logs de scan (gerados automaticamente)
└── reports/                            # Relatórios de vulnerabilidades (gerados)
```

## 🛡️ O que o Scanner Detecta

### Categorias de Vulnerabilidade

| Categoria | Severidade | Descrição |
|-----------|-----------|-----------|
| `CODE_INJECTION` | 🔴 CRITICAL | `loadstring`, require dinâmico |
| `MEMORY_MANIPULATION` | 🔴 CRITICAL | `getrawmetatable`, `hookfunction`, `hookmetamethod` |
| `DATA_EXFILTRATION` | 🟠 HIGH | `HttpGet`, `HttpPost`, `syn.request` para domínios externos |
| `PRIVILEGE_ESCALATION` | 🟠 HIGH | `getgenv`, `getrenv`, `debug.setupvalue` |
| `AUTHENTICATION_BYPASS` | 🟠 HIGH | `getnamecallmethod`, `setnamecallmethod` |
| `REMOTE_ABUSE` | 🟡 MEDIUM | RemoteEvents sem validação, sem rate limiting |
| `INPUT_VALIDATION` | 🟡 MEDIUM | `fireclickdetector`, `firetouchinterest`, `fireproximityprompt` |

### Padrões Monitorados

- **30+ padrões** de funções de exploit conhecidas
- **Nomes suspeitos** de RemoteEvents/Functions
- **Domínios não autorizados** em requisições HTTP
- **Argumentos maliciosos** em Remote calls (overflow, código embutido, nesting excessivo)

## 📊 Saída em JSON

Todos os logs e relatórios são salvos em JSON estruturado:

```json
{
  "report_version": "1.0.0",
  "generated_at": "2026-04-16T10:00:00Z",
  "summary": {
    "total_vulnerabilities": 5,
    "by_severity": { "CRITICAL": 2, "HIGH": 2, "MEDIUM": 1, "LOW": 0 },
    "risk_level": "CRITICAL"
  },
  "vulnerabilities": [
    {
      "vuln_id": "VULN-CI-001",
      "name": "Uso de loadstring",
      "severity": "CRITICAL",
      "source": "Game.Workspace.MaliciousScript",
      "line_number": 3,
      "remediation": "Evitar loadstring. Usar módulos pré-compilados."
    }
  ],
  "recommendations": [...]
}
```

### Arquivos Gerados (pasta `ScanningLua/`)

| Arquivo | Conteúdo |
|---------|----------|
| `logs/scan_log_*.json` | Todos os logs da sessão |
| `reports/scan_results_*.json` | Resultados do scan (remotes, scripts, itens suspeitos) |
| `reports/vuln_report_*.json` | Relatório de vulnerabilidades com recomendações |
| `reports/network_*.json` | Tráfego de rede e alertas |

## ⚙️ API Completa

| Método | Descrição |
|--------|-----------|
| `ScanningLua.fullScan([game])` | Scan completo de todos os serviços |
| `ScanningLua.scanCode(code, name)` | Analisar string de código Lua |
| `ScanningLua.scanScript(instance)` | Analisar instância de script |
| `ScanningLua.monitorRemote(remote, cb)` | Monitorar um RemoteEvent |
| `ScanningLua.monitorAllRemotes(cb)` | Monitorar todos os RemoteEvents |
| `ScanningLua.logHTTPRequest(method, url)` | Registrar requisição HTTP |
| `ScanningLua.saveAllResults()` | Salvar todos os relatórios em JSON |
| `ScanningLua.getVulnerabilityReport()` | Retorna relatório como tabela |
| `ScanningLua.getVulnerabilityReportJSON()` | Retorna relatório como JSON string |
| `ScanningLua.getStats()` | Retorna estatísticas gerais |
| `ScanningLua.printSummary()` | Imprime resumo no console |
| `ScanningLua.reset()` | Limpa todos os dados |
| `ScanningLua.shutdown()` | Encerra e salva tudo |

## 🔧 Executando Localmente (Lua 5.1+)

```bash
cd Scanning-Lua
lua main.lua
```

Executa uma demonstração com dados simulados e gera relatórios nos diretórios `logs/` e `reports/`.

## 📝 Licença

Projeto para fins educacionais e de pesquisa em segurança.