--[[
    Scanning-Lua - GUI Module (#27)
    Interface gráfica interativa para Roblox

    Features:
    - Janela draggable com título
    - Sistema de abas (Overview, Vulns, Heuristic, Signatures, Network, Resultados)
    - Botões de copiar para cada resultado/retorno
    - Cores por severidade (CRITICAL ⚫, HIGH 🔴, MEDIUM 🟠, LOW 🟡, NONE 🟢)
    - Barra de risco visual
    - Busca/filtro de resultados
    - Minimizar/fechar
    - ScrollingFrames para conteúdo longo
    - Exportar todos os resultados
    - Animações suaves
]]

local ScannerGui = {}
ScannerGui.__index = ScannerGui

-- ============================================================
-- Compatibilidade com ambientes não-Roblox
-- Garante que carregar este módulo fora do Roblox (ex.: rodar o demo
-- com `lua main.lua`) não quebre por causa de globals como Color3.
-- Em Roblox, usamos a API real; fora dele, um stub neutro.
-- ============================================================
local Color3 = rawget(_G, "Color3") or {
    fromRGB = function(r, g, b)
        return { R = (r or 0) / 255, G = (g or 0) / 255, B = (b or 0) / 255 }
    end,
}

-- ============================================================
-- Cores e constantes do tema
-- ============================================================
local COLORS = {
    -- Fundo principal
    BG_DARK = Color3.fromRGB(18, 18, 24),
    BG_MEDIUM = Color3.fromRGB(25, 25, 35),
    BG_LIGHT = Color3.fromRGB(35, 35, 50),
    BG_CARD = Color3.fromRGB(30, 30, 42),

    -- Acentos
    ACCENT = Color3.fromRGB(88, 101, 242),
    ACCENT_HOVER = Color3.fromRGB(108, 121, 255),
    ACCENT_DIM = Color3.fromRGB(60, 70, 180),

    -- Texto
    TEXT_PRIMARY = Color3.fromRGB(230, 230, 240),
    TEXT_SECONDARY = Color3.fromRGB(160, 160, 180),
    TEXT_DIM = Color3.fromRGB(100, 100, 120),

    -- Severidade
    CRITICAL = Color3.fromRGB(30, 30, 30),
    HIGH = Color3.fromRGB(220, 50, 50),
    MEDIUM = Color3.fromRGB(255, 165, 0),
    LOW = Color3.fromRGB(255, 215, 0),
    NONE = Color3.fromRGB(50, 205, 50),

    -- Feedback
    SUCCESS = Color3.fromRGB(50, 205, 50),
    COPY_FLASH = Color3.fromRGB(88, 101, 242),
    BORDER = Color3.fromRGB(50, 50, 70),
    BORDER_ACTIVE = Color3.fromRGB(88, 101, 242),

    -- Tab
    TAB_INACTIVE = Color3.fromRGB(40, 40, 55),
    TAB_ACTIVE = Color3.fromRGB(88, 101, 242),
    TAB_HOVER = Color3.fromRGB(50, 50, 70),

    -- Botões
    BTN_COPY = Color3.fromRGB(55, 55, 75),
    BTN_COPY_HOVER = Color3.fromRGB(70, 70, 95),
    BTN_CLOSE = Color3.fromRGB(220, 50, 50),
    BTN_MINIMIZE = Color3.fromRGB(255, 165, 0),
}

local SEVERITY_COLORS = {
    CRITICAL = COLORS.CRITICAL,
    HIGH = COLORS.HIGH,
    MEDIUM = COLORS.MEDIUM,
    LOW = COLORS.LOW,
    NONE = COLORS.NONE,
}

local SEVERITY_EMOJIS = {
    CRITICAL = "⚫",
    HIGH = "🔴",
    MEDIUM = "🟠",
    LOW = "🟡",
    NONE = "🟢",
}

local FONT_SIZES = {
    TITLE = 18,
    SUBTITLE = 15,
    BODY = 14,
    SMALL = 12,
    TINY = 11,
}

local function buildDefaultResults()
    return {
        scanner = { scripts_analyzed = 0, remote_events = 0, remote_functions = 0, suspicious_items = 0 },
        vulnerabilities = { by_severity = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0 }, details = {} },
        network = { total_requests = 0, suspicious_requests = 0, requests = {} },
        heuristic = { total_analyzed = 0, max_score = 0, average_score = 0, analyses = {} },
        signatures = { detections = {} },
        log_entries = {},
    }
end

-- ============================================================
-- Utilitários internos
-- ============================================================
local function truncate(str, maxLen)
    maxLen = maxLen or 80
    if #str > maxLen then
        return str:sub(1, maxLen - 3) .. "..."
    end
    return str
end

local function formatNumber(n)
    if not n then return "0" end
    n = tostring(n)
    local result = ""
    local len = #n
    for i = 1, len do
        if i > 1 and (len - i + 1) % 3 == 0 then
            result = result .. ","
        end
        result = result .. n:sub(i, i)
    end
    return result
end

local function safeTostring(v)
    if type(v) == "table" then
        local ok, result = pcall(function()
            local parts = {}
            local count = 0
            local totalCount = 0
            for _ in pairs(v) do totalCount = totalCount + 1 end
            for k, val in pairs(v) do
                count = count + 1
                if count > 20 then
                    parts[#parts + 1] = "... (+" .. (totalCount - 20) .. " more)"
                    break
                end
                parts[#parts + 1] = tostring(k) .. " = " .. tostring(val)
            end
            return "{ " .. table.concat(parts, ", ") .. " }"
        end)
        if ok then return result end
        return "{table}"
    end
    return tostring(v)
end

-- ============================================================
-- Construtor
-- ============================================================

--- Cria nova instância do GUI
--- @param config table Configurações do GUI
--- @param logger table Instância do Logger (opcional)
--- @return table ScannerGui
function ScannerGui.new(config, logger)
    local self = setmetatable({}, ScannerGui)
    self.config = config or {}
    self.logger = logger
    self.gui = nil
    self.mainFrame = nil
    self.isMinimized = false
    self.isVisible = false
    self.currentTab = "overview"
    self.tabs = {}
    self.tabPages = {}
    self.connections = {}
    self.lastResults = nil
    self.searchFilter = ""
    self.searchDebounceToken = 0
    return self
end

-- ============================================================
-- Criação da GUI principal
-- ============================================================

--- Cria elemento de UI com propriedades
--- @param className string Classe do Instance
--- @param props table Propriedades
--- @return Instance
function ScannerGui:_create(className, props)
    local inst = Instance.new(className)
    for k, v in pairs(props or {}) do
        if k ~= "Parent" and k ~= "Children" then
            pcall(function() inst[k] = v end)
        end
    end
    if props and props.Children then
        for _, child in ipairs(props.Children) do
            child.Parent = inst
        end
    end
    if props and props.Parent then
        inst.Parent = props.Parent
    end
    return inst
end

--- Cria UICorner
function ScannerGui:_corner(parent, radius)
    return self:_create("UICorner", {
        CornerRadius = UDim.new(0, radius or 8),
        Parent = parent,
    })
end

--- Cria UIStroke (borda)
function ScannerGui:_stroke(parent, color, thickness)
    return self:_create("UIStroke", {
        Color = color or COLORS.BORDER,
        Thickness = thickness or 1,
        Parent = parent,
    })
end

--- Cria UIPadding
function ScannerGui:_padding(parent, top, right, bottom, left)
    return self:_create("UIPadding", {
        PaddingTop = UDim.new(0, top or 8),
        PaddingRight = UDim.new(0, right or 8),
        PaddingBottom = UDim.new(0, bottom or 8),
        PaddingLeft = UDim.new(0, left or 8),
        Parent = parent,
    })
end

--- Cria UIListLayout
function ScannerGui:_listLayout(parent, padding, direction, halign, valign)
    return self:_create("UIListLayout", {
        Padding = UDim.new(0, padding or 4),
        FillDirection = direction or Enum.FillDirection.Vertical,
        HorizontalAlignment = halign or Enum.HorizontalAlignment.Left,
        VerticalAlignment = valign or Enum.VerticalAlignment.Top,
        SortOrder = Enum.SortOrder.LayoutOrder,
        Parent = parent,
    })
end

--- Conecta evento e armazena connection para cleanup
function ScannerGui:_connect(signal, callback)
    if not signal or not callback then
        if self.logger and self.logger.warn then
            self.logger:warn("GUI", "Falha ao conectar evento: signal/callback inválido")
        end
        return nil
    end
    local ok, conn = pcall(function()
        return signal:Connect(callback)
    end)
    if ok and conn then
        self.connections[#self.connections + 1] = conn
        return conn
    end
    if self.logger and self.logger.warn then
        self.logger:warn("GUI", "Falha ao conectar evento de GUI", { has_signal = signal ~= nil, has_callback = callback ~= nil })
    end
    return nil
end

--- Copia texto para clipboard
function ScannerGui:_copyToClipboard(text)
    pcall(function()
        if setclipboard then
            setclipboard(tostring(text))
        elseif toclipboard then
            toclipboard(tostring(text))
        elseif Clipboard and Clipboard.set then
            Clipboard.set(tostring(text))
        end
    end)
end

--- Flash visual ao copiar
function ScannerGui:_flashCopy(button, originalColor)
    pcall(function()
        local origText = button.Text
        button.Text = "✓ Copiado!"
        button.BackgroundColor3 = COLORS.SUCCESS
        task.delay(0.8, function()
            pcall(function()
                button.Text = origText
                button.BackgroundColor3 = originalColor or COLORS.BTN_COPY
            end)
        end)
    end)
end

--- Cria botão de copiar compacto
--- @param parent Instance Parent
--- @param textToCopy string Texto a copiar
--- @param layoutOrder number Ordem no layout
--- @return Instance
function ScannerGui:_createCopyButton(parent, textToCopy, layoutOrder)
    local btn = self:_create("TextButton", {
        Size = UDim2.new(0, 60, 0, 22),
        BackgroundColor3 = COLORS.BTN_COPY,
        Text = "📋 Copy",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.TINY,
        Font = Enum.Font.GothamMedium,
        AutoButtonColor = false,
        LayoutOrder = layoutOrder or 0,
        Parent = parent,
    })
    self:_corner(btn, 4)

    self:_connect(btn.MouseEnter, function()
        btn.BackgroundColor3 = COLORS.BTN_COPY_HOVER
    end)
    self:_connect(btn.MouseLeave, function()
        btn.BackgroundColor3 = COLORS.BTN_COPY
    end)
    self:_connect(btn.MouseButton1Click, function()
        self:_copyToClipboard(textToCopy)
        self:_flashCopy(btn, COLORS.BTN_COPY)
    end)

    return btn
end

--- Cria card de resultado com botão de copiar
--- @param parent Instance ScrollingFrame ou Frame pai
--- @param title string Título do resultado
--- @param content string Conteúdo/valor
--- @param severity string Severidade (CRITICAL, HIGH, MEDIUM, LOW, NONE)
--- @param layoutOrder number Ordem no layout
--- @return Instance
function ScannerGui:_createResultCard(parent, title, content, severity, layoutOrder)
    severity = severity or "NONE"
    local sevColor = SEVERITY_COLORS[severity] or COLORS.TEXT_DIM
    local emoji = SEVERITY_EMOJIS[severity] or ""

    local card = self:_create("Frame", {
        Size = UDim2.new(1, -8, 0, 0),
        AutomaticSize = Enum.AutomaticSize.Y,
        BackgroundColor3 = COLORS.BG_CARD,
        LayoutOrder = layoutOrder or 0,
        Parent = parent,
    })
    self:_corner(card, 6)
    self:_padding(card, 8, 10, 8, 10)

    -- Indicador de severidade na lateral esquerda
    local sevIndicator = self:_create("Frame", {
        Size = UDim2.new(0, 3, 1, -8),
        Position = UDim2.new(0, 0, 0, 4),
        BackgroundColor3 = sevColor,
        BorderSizePixel = 0,
        Parent = card,
    })
    self:_corner(sevIndicator, 2)

    -- Conteúdo
    local contentFrame = self:_create("Frame", {
        Size = UDim2.new(1, -12, 0, 0),
        Position = UDim2.new(0, 12, 0, 0),
        AutomaticSize = Enum.AutomaticSize.Y,
        BackgroundTransparency = 1,
        Parent = card,
    })
    self:_listLayout(contentFrame, 3)

    -- Header com título e botão copiar
    local header = self:_create("Frame", {
        Size = UDim2.new(1, 0, 0, 22),
        BackgroundTransparency = 1,
        LayoutOrder = 1,
        Parent = contentFrame,
    })

    self:_create("TextLabel", {
        Size = UDim2.new(1, -70, 1, 0),
        BackgroundTransparency = 1,
        Text = emoji .. " " .. title,
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.BODY,
        Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Left,
        TextTruncate = Enum.TextTruncate.AtEnd,
        LayoutOrder = 1,
        Parent = header,
    })

    -- Botão copiar no canto
    local copyBtn = self:_create("TextButton", {
        Size = UDim2.new(0, 60, 0, 20),
        Position = UDim2.new(1, -60, 0, 1),
        BackgroundColor3 = COLORS.BTN_COPY,
        Text = "📋 Copy",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.TINY,
        Font = Enum.Font.GothamMedium,
        AutoButtonColor = false,
        Parent = header,
    })
    self:_corner(copyBtn, 4)

    local copyText = title .. "\n" .. content
    self:_connect(copyBtn.MouseEnter, function()
        copyBtn.BackgroundColor3 = COLORS.BTN_COPY_HOVER
    end)
    self:_connect(copyBtn.MouseLeave, function()
        copyBtn.BackgroundColor3 = COLORS.BTN_COPY
    end)
    self:_connect(copyBtn.MouseButton1Click, function()
        self:_copyToClipboard(copyText)
        self:_flashCopy(copyBtn, COLORS.BTN_COPY)
    end)

    -- Conteúdo do resultado
    self:_create("TextLabel", {
        Size = UDim2.new(1, 0, 0, 0),
        AutomaticSize = Enum.AutomaticSize.Y,
        BackgroundTransparency = 1,
        Text = content,
        TextColor3 = COLORS.TEXT_SECONDARY,
        TextSize = FONT_SIZES.SMALL,
        Font = Enum.Font.Gotham,
        TextXAlignment = Enum.TextXAlignment.Left,
        TextWrapped = true,
        RichText = true,
        LayoutOrder = 2,
        Parent = contentFrame,
    })

    -- Badge de severidade
    if severity ~= "NONE" then
        local badge = self:_create("TextLabel", {
            Size = UDim2.new(0, 0, 0, 18),
            AutomaticSize = Enum.AutomaticSize.X,
            BackgroundColor3 = sevColor,
            BackgroundTransparency = severity == "CRITICAL" and 0 or 0.7,
            Text = "  " .. severity .. "  ",
            TextColor3 = severity == "CRITICAL" and Color3.fromRGB(255, 60, 60) or COLORS.TEXT_PRIMARY,
            TextSize = FONT_SIZES.TINY,
            Font = Enum.Font.GothamBold,
            LayoutOrder = 3,
            Parent = contentFrame,
        })
        self:_corner(badge, 4)
    end

    return card
end

--- Cria barra de estatísticas
function ScannerGui:_createStatBar(parent, label, value, maxValue, color, layoutOrder)
    local frame = self:_create("Frame", {
        Size = UDim2.new(1, -4, 0, 36),
        BackgroundTransparency = 1,
        LayoutOrder = layoutOrder or 0,
        Parent = parent,
    })

    self:_create("TextLabel", {
        Size = UDim2.new(0.5, 0, 0, 16),
        BackgroundTransparency = 1,
        Text = label,
        TextColor3 = COLORS.TEXT_SECONDARY,
        TextSize = FONT_SIZES.SMALL,
        Font = Enum.Font.Gotham,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = frame,
    })

    self:_create("TextLabel", {
        Size = UDim2.new(0.5, 0, 0, 16),
        BackgroundTransparency = 1,
        Text = tostring(value),
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.SMALL,
        Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Right,
        Parent = frame,
    })

    -- Barra de progresso
    local barBg = self:_create("Frame", {
        Size = UDim2.new(1, 0, 0, 6),
        Position = UDim2.new(0, 0, 0, 22),
        BackgroundColor3 = COLORS.BG_LIGHT,
        Parent = frame,
    })
    self:_corner(barBg, 3)

    local pct = maxValue > 0 and math.min(value / maxValue, 1) or 0
    local barFill = self:_create("Frame", {
        Size = UDim2.new(pct, 0, 1, 0),
        BackgroundColor3 = color or COLORS.ACCENT,
        Parent = barBg,
    })
    self:_corner(barFill, 3)

    return frame
end

-- ============================================================
-- Construir interface principal
-- ============================================================

--- Constrói a GUI completa
--- @return ScreenGui
function ScannerGui:build()
    -- Remover GUI anterior se existir
    self:destroy()

    -- Encontrar o melhor parent para a GUI
    local guiParent
    pcall(function()
        if gethui then
            guiParent = gethui()
        elseif syn and syn.protect_gui then
            guiParent = game:GetService("CoreGui")
        else
            guiParent = game:GetService("CoreGui")
        end
    end)
    if not guiParent then
        pcall(function()
            guiParent = game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui")
        end)
    end
    if not guiParent then
        pcall(function()
            local players = game:GetService("Players")
            local lp = players and players.LocalPlayer
            guiParent = lp and lp:FindFirstChildOfClass("PlayerGui") or nil
        end)
    end
    if not guiParent then
        pcall(function()
            guiParent = game:GetService("CoreGui")
        end)
    end

    -- ScreenGui
    self.gui = self:_create("ScreenGui", {
        Name = "ScanningLuaGUI",
        ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
        ResetOnSpawn = false,
        DisplayOrder = 999,
        Parent = guiParent,
    })

    -- Proteger a GUI (se disponível)
    pcall(function()
        if syn and syn.protect_gui then
            syn.protect_gui(self.gui)
        end
    end)

    -- Frame principal
    self.mainFrame = self:_create("Frame", {
        Name = "MainWindow",
        Size = UDim2.new(0, 580, 0, 480),
        Position = UDim2.new(0.5, -290, 0.5, -240),
        BackgroundColor3 = COLORS.BG_DARK,
        BorderSizePixel = 0,
        Parent = self.gui,
    })
    self:_corner(self.mainFrame, 12)
    self:_stroke(self.mainFrame, COLORS.BORDER, 1)

    -- Drop shadow
    local shadow = self:_create("ImageLabel", {
        Name = "Shadow",
        Size = UDim2.new(1, 30, 1, 30),
        Position = UDim2.new(0, -15, 0, -15),
        BackgroundTransparency = 1,
        Image = "rbxassetid://5554236805",
        ImageColor3 = Color3.fromRGB(0, 0, 0),
        ImageTransparency = 0.5,
        ScaleType = Enum.ScaleType.Slice,
        SliceCenter = Rect.new(23, 23, 277, 277),
        ZIndex = -1,
        Parent = self.mainFrame,
    })

    -- ========== TITLE BAR ==========
    local titleBar = self:_create("Frame", {
        Name = "TitleBar",
        Size = UDim2.new(1, 0, 0, 40),
        BackgroundColor3 = COLORS.BG_MEDIUM,
        BorderSizePixel = 0,
        Parent = self.mainFrame,
    })
    self:_corner(titleBar, 12)

    -- Arredondar só em cima
    local titleBarBlockBottom = self:_create("Frame", {
        Size = UDim2.new(1, 0, 0, 12),
        Position = UDim2.new(0, 0, 1, -12),
        BackgroundColor3 = COLORS.BG_MEDIUM,
        BorderSizePixel = 0,
        Parent = titleBar,
    })

    -- Ícone e título (width shrunk to accommodate the extra Refresh button)
    self:_create("TextLabel", {
        Size = UDim2.new(1, -160, 1, 0),
        Position = UDim2.new(0, 14, 0, 0),
        BackgroundTransparency = 1,
        Text = "🔒 Scanning-Lua v3.0.0",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.SUBTITLE,
        Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Left,
        Parent = titleBar,
    })

    -- Botão minimizar
    local minimizeBtn = self:_create("TextButton", {
        Name = "Minimize",
        Size = UDim2.new(0, 30, 0, 30),
        Position = UDim2.new(1, -70, 0, 5),
        BackgroundColor3 = COLORS.BTN_MINIMIZE,
        BackgroundTransparency = 0.5,
        Text = "─",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.BODY,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        Parent = titleBar,
    })
    self:_corner(minimizeBtn, 6)

    self:_connect(minimizeBtn.MouseButton1Click, function()
        self:toggleMinimize()
    end)

    -- Botão fechar
    local closeBtn = self:_create("TextButton", {
        Name = "Close",
        Size = UDim2.new(0, 30, 0, 30),
        Position = UDim2.new(1, -36, 0, 5),
        BackgroundColor3 = COLORS.BTN_CLOSE,
        BackgroundTransparency = 0.5,
        Text = "✕",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.BODY,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        Parent = titleBar,
    })
    self:_corner(closeBtn, 6)

    self:_connect(closeBtn.MouseButton1Click, function()
        self:hide()
    end)

    -- Botão refresh (↺) — fica à esquerda do minimize
    local refreshBtn = self:_create("TextButton", {
        Name = "Refresh",
        Size = UDim2.new(0, 30, 0, 30),
        Position = UDim2.new(1, -106, 0, 5),
        BackgroundColor3 = COLORS.ACCENT,
        BackgroundTransparency = 0.5,
        Text = "↺",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.BODY,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        Parent = titleBar,
    })
    self:_corner(refreshBtn, 6)

    self:_connect(refreshBtn.MouseButton1Click, function()
        if self.lastResults then
            self:update(self.lastResults)
        else
            self:update(buildDefaultResults())
        end
    end)

    -- Hover effects nos botões de controle
    for _, btn in ipairs({minimizeBtn, closeBtn, refreshBtn}) do
        self:_connect(btn.MouseEnter, function()
            btn.BackgroundTransparency = 0.2
        end)
        self:_connect(btn.MouseLeave, function()
            btn.BackgroundTransparency = 0.5
        end)
    end

    -- Dragging
    self:_setupDragging(titleBar)

    -- ========== CONTENT AREA ==========
    local content = self:_create("Frame", {
        Name = "Content",
        Size = UDim2.new(1, -16, 1, -48),
        Position = UDim2.new(0, 8, 0, 44),
        BackgroundTransparency = 1,
        ClipsDescendants = true,
        Parent = self.mainFrame,
    })
    self.contentFrame = content

    -- ========== TAB BAR ==========
    local tabBar = self:_create("Frame", {
        Name = "TabBar",
        Size = UDim2.new(1, 0, 0, 32),
        BackgroundTransparency = 1,
        Parent = content,
    })

    local tabBarLayout = self:_create("UIListLayout", {
        FillDirection = Enum.FillDirection.Horizontal,
        Padding = UDim.new(0, 4),
        HorizontalAlignment = Enum.HorizontalAlignment.Left,
        SortOrder = Enum.SortOrder.LayoutOrder,
        Parent = tabBar,
    })

    local tabDefs = {
        { id = "overview",  label = "📊 Overview",    order = 1 },
        { id = "vulns",     label = "🛡️ Vulns",       order = 2 },
        { id = "heuristic", label = "🧠 Heuristic",   order = 3 },
        { id = "sigs",      label = "🧩 Signatures",  order = 4 },
        { id = "network",   label = "📡 Network",     order = 5 },
        { id = "advanced",  label = "🔬 Advanced",    order = 6 },
        { id = "results",   label = "📋 Resultados",  order = 7 },
    }

    for _, tabDef in ipairs(tabDefs) do
        local isActive = tabDef.id == self.currentTab
        local tabBtn = self:_create("TextButton", {
            Name = "Tab_" .. tabDef.id,
            Size = UDim2.new(0, 0, 1, -4),
            AutomaticSize = Enum.AutomaticSize.X,
            BackgroundColor3 = isActive and COLORS.TAB_ACTIVE or COLORS.TAB_INACTIVE,
            Text = "  " .. tabDef.label .. "  ",
            TextColor3 = COLORS.TEXT_PRIMARY,
            TextSize = FONT_SIZES.SMALL,
            Font = isActive and Enum.Font.GothamBold or Enum.Font.Gotham,
            AutoButtonColor = false,
            LayoutOrder = tabDef.order,
            Parent = tabBar,
        })
        self:_corner(tabBtn, 6)

        self.tabs[tabDef.id] = tabBtn

        self:_connect(tabBtn.MouseEnter, function()
            if self.currentTab ~= tabDef.id then
                tabBtn.BackgroundColor3 = COLORS.TAB_HOVER
            end
        end)
        self:_connect(tabBtn.MouseLeave, function()
            if self.currentTab ~= tabDef.id then
                tabBtn.BackgroundColor3 = COLORS.TAB_INACTIVE
            end
        end)
        self:_connect(tabBtn.MouseButton1Click, function()
            self:switchTab(tabDef.id)
        end)
    end

    -- ========== SEARCH BAR ==========
    local searchBar = self:_create("Frame", {
        Name = "SearchBar",
        Size = UDim2.new(1, 0, 0, 30),
        Position = UDim2.new(0, 0, 0, 36),
        BackgroundColor3 = COLORS.BG_LIGHT,
        Parent = content,
    })
    self:_corner(searchBar, 6)

    local searchIcon = self:_create("TextLabel", {
        Size = UDim2.new(0, 28, 1, 0),
        BackgroundTransparency = 1,
        Text = "🔍",
        TextSize = FONT_SIZES.BODY,
        Parent = searchBar,
    })

    local searchInput = self:_create("TextBox", {
        Name = "SearchInput",
        Size = UDim2.new(1, -100, 1, 0),
        Position = UDim2.new(0, 28, 0, 0),
        BackgroundTransparency = 1,
        PlaceholderText = "Buscar resultados...",
        PlaceholderColor3 = COLORS.TEXT_DIM,
        Text = "",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.SMALL,
        Font = Enum.Font.Gotham,
        TextXAlignment = Enum.TextXAlignment.Left,
        ClearTextOnFocus = false,
        Parent = searchBar,
    })
    self.searchBox = searchInput

    self:_connect(searchInput:GetPropertyChangedSignal("Text"), function()
        self.searchFilter = searchInput.Text:lower()
        -- Debounce: only refresh after 0.3 s of inactivity to avoid freezing on large lists
        self.searchDebounceToken = self.searchDebounceToken + 1
        local token = self.searchDebounceToken
        pcall(function()
            task.delay(0.3, function()
                if self.searchDebounceToken == token then
                    self:_refreshCurrentTab()
                end
            end)
        end)
    end)

    -- Botão "Copiar Tudo"
    local copyAllBtn = self:_create("TextButton", {
        Name = "CopyAll",
        Size = UDim2.new(0, 68, 0, 24),
        Position = UDim2.new(1, -70, 0, 3),
        BackgroundColor3 = COLORS.ACCENT,
        Text = "📋 Copiar",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.TINY,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        Parent = searchBar,
    })
    self:_corner(copyAllBtn, 4)

    self:_connect(copyAllBtn.MouseEnter, function()
        copyAllBtn.BackgroundColor3 = COLORS.ACCENT_HOVER
    end)
    self:_connect(copyAllBtn.MouseLeave, function()
        copyAllBtn.BackgroundColor3 = COLORS.ACCENT
    end)
    self:_connect(copyAllBtn.MouseButton1Click, function()
        self:copyAllResults()
        self:_flashCopy(copyAllBtn, COLORS.ACCENT)
    end)

    -- ========== TAB PAGES ==========
    local pagesFrame = self:_create("Frame", {
        Name = "Pages",
        Size = UDim2.new(1, 0, 1, -72),
        Position = UDim2.new(0, 0, 0, 70),
        BackgroundTransparency = 1,
        ClipsDescendants = true,
        Parent = content,
    })

    for _, tabDef in ipairs(tabDefs) do
        local page = self:_create("ScrollingFrame", {
            Name = "Page_" .. tabDef.id,
            Size = UDim2.new(1, 0, 1, 0),
            BackgroundTransparency = 1,
            ScrollBarThickness = 4,
            ScrollBarImageColor3 = COLORS.ACCENT_DIM,
            CanvasSize = UDim2.new(0, 0, 0, 0),
            AutomaticCanvasSize = Enum.AutomaticCanvasSize.Y,
            Visible = tabDef.id == self.currentTab,
            Parent = pagesFrame,
        })
        self:_listLayout(page, 6)
        self:_padding(page, 4, 8, 4, 4)

        self.tabPages[tabDef.id] = page
    end

    -- Hotkey: RightControl para toggle da GUI (somente no Roblox)
    pcall(function()
        local UIS = game:GetService("UserInputService")
        self:_connect(UIS.InputBegan, function(input, gameProcessed)
            if gameProcessed then return end
            if input.KeyCode == Enum.KeyCode.RightControl then
                self:toggle()
            end
        end)
    end)

    self.isVisible = true
    return self.gui
end

--- Configura dragging do título
function ScannerGui:_setupDragging(titleBar)
    local dragging = false
    local dragStart, startPos

    -- localConn is the per-drag input.Changed handler.
    -- It is NOT stored in self.connections; it disconnects itself when the drag ends
    -- so the same slot is reused on the next drag, preventing connection leaks.
    local localConn

    self:_connect(titleBar.InputBegan, function(input)
        if input.UserInputType == Enum.UserInputType.MouseButton1 or
           input.UserInputType == Enum.UserInputType.Touch then
            dragging = true
            dragStart = input.Position
            startPos = self.mainFrame.Position

            -- Disconnect leftover handler from a previous drag
            if localConn then
                pcall(function() localConn:Disconnect() end)
                localConn = nil
            end

            -- Connect directly (bypassing self:_connect) so it can be cleaned up early
            pcall(function()
                localConn = input.Changed:Connect(function()
                    if input.UserInputState == Enum.UserInputState.End then
                        dragging = false
                        if localConn then
                            localConn:Disconnect()
                            localConn = nil
                        end
                    end
                end)
            end)
        end
    end)

    self:_connect(titleBar.InputChanged, function(input)
        if dragging and (input.UserInputType == Enum.UserInputType.MouseMovement or
           input.UserInputType == Enum.UserInputType.Touch) then
            local delta = input.Position - dragStart
            local newX = startPos.X.Offset + delta.X
            local newY = startPos.Y.Offset + delta.Y

            -- Clamp within viewport so the window cannot be moved off-screen
            pcall(function()
                local vp = workspace.CurrentCamera.ViewportSize
                local winW = self.mainFrame.AbsoluteSize.X
                local winH = self.mainFrame.AbsoluteSize.Y
                newX = math.clamp(newX, -(winW * 0.9), vp.X - (winW * 0.1))
                newY = math.clamp(newY, 0, vp.Y - (winH * 0.1))
            end)

            self.mainFrame.Position = UDim2.new(
                startPos.X.Scale, newX,
                startPos.Y.Scale, newY
            )
        end
    end)
end

-- ============================================================
-- Navegação de abas
-- ============================================================

--- Troca para uma aba
--- @param tabId string ID da aba
function ScannerGui:switchTab(tabId)
    if self.currentTab == tabId then return end

    -- Desativar aba anterior
    if self.tabs[self.currentTab] then
        self.tabs[self.currentTab].BackgroundColor3 = COLORS.TAB_INACTIVE
        self.tabs[self.currentTab].Font = Enum.Font.Gotham
    end
    if self.tabPages[self.currentTab] then
        self.tabPages[self.currentTab].Visible = false
    end

    -- Ativar nova aba
    self.currentTab = tabId
    if self.tabs[tabId] then
        self.tabs[tabId].BackgroundColor3 = COLORS.TAB_ACTIVE
        self.tabs[tabId].Font = Enum.Font.GothamBold
    end
    if self.tabPages[tabId] then
        self.tabPages[tabId].Visible = true
    end

    -- Refresh conteúdo
    self:_refreshCurrentTab()
end

--- Limpa conteúdo de uma página
function ScannerGui:_clearPage(pageId)
    local page = self.tabPages[pageId]
    if not page then return end
    for _, child in ipairs(page:GetChildren()) do
        if not child:IsA("UIListLayout") and not child:IsA("UIPadding") then
            child:Destroy()
        end
    end
    -- Reset scroll to top so re-populated content starts at the beginning
    pcall(function() page.CanvasPosition = Vector2.new(0, 0) end)
end

--- Refresh da aba atual
function ScannerGui:_refreshCurrentTab()
    local results = self.lastResults or buildDefaultResults()
    self:populateTab(self.currentTab, results)
end

-- ============================================================
-- Popular abas com dados
-- ============================================================

--- Popula uma aba com dados
--- @param tabId string ID da aba
--- @param data table Dados do scan
function ScannerGui:populateTab(tabId, data)
    self:_clearPage(tabId)
    local page = self.tabPages[tabId]
    if not page then return end

    if tabId == "overview" then
        self:_populateOverview(page, data)
    elseif tabId == "vulns" then
        self:_populateVulns(page, data)
    elseif tabId == "heuristic" then
        self:_populateHeuristic(page, data)
    elseif tabId == "sigs" then
        self:_populateSignatures(page, data)
    elseif tabId == "network" then
        self:_populateNetwork(page, data)
    elseif tabId == "advanced" then
        self:_populateAdvanced(page, data)
    elseif tabId == "results" then
        self:_populateResults(page, data)
    end
end

--- Cria seção com título
function ScannerGui:_createSection(parent, title, layoutOrder)
    local section = self:_create("Frame", {
        Size = UDim2.new(1, -4, 0, 0),
        AutomaticSize = Enum.AutomaticSize.Y,
        BackgroundColor3 = COLORS.BG_MEDIUM,
        LayoutOrder = layoutOrder or 0,
        Parent = parent,
    })
    self:_corner(section, 8)
    self:_padding(section, 10, 12, 10, 12)
    self:_listLayout(section, 6)

    self:_create("TextLabel", {
        Size = UDim2.new(1, 0, 0, 22),
        BackgroundTransparency = 1,
        Text = title,
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.SUBTITLE,
        Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Left,
        LayoutOrder = 0,
        Parent = section,
    })

    return section
end

--- Popula aba Overview
function ScannerGui:_populateOverview(page, data)
    local scanner = data.scanner or {}
    local vuln = data.vulnerabilities or {}
    local bySev = vuln.by_severity or {}
    local heuristic = data.heuristic or {}

    -- Risk Level Card
    local riskSection = self:_createSection(page, "⚡ Risk Level", 1)

    local totalVuln = (bySev.CRITICAL or 0) + (bySev.HIGH or 0) +
        (bySev.MEDIUM or 0) + (bySev.LOW or 0)
    local riskLevel = "NONE"
    if (bySev.CRITICAL or 0) > 0 then riskLevel = "CRITICAL"
    elseif (bySev.HIGH or 0) > 0 then riskLevel = "HIGH"
    elseif (bySev.MEDIUM or 0) > 0 then riskLevel = "MEDIUM"
    elseif (bySev.LOW or 0) > 0 then riskLevel = "LOW" end

    local riskColor = SEVERITY_COLORS[riskLevel] or COLORS.NONE
    local riskEmoji = SEVERITY_EMOJIS[riskLevel] or "🟢"

    self:_create("TextLabel", {
        Size = UDim2.new(1, 0, 0, 30),
        BackgroundTransparency = 1,
        Text = riskEmoji .. " " .. riskLevel .. "  —  " .. totalVuln .. " vulnerabilidades detectadas",
        TextColor3 = riskLevel == "CRITICAL" and Color3.fromRGB(255, 60, 60) or riskColor,
        TextSize = FONT_SIZES.TITLE,
        Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Left,
        LayoutOrder = 1,
        Parent = riskSection,
    })

    -- Barra de risco visual
    local barBg = self:_create("Frame", {
        Size = UDim2.new(1, 0, 0, 10),
        BackgroundColor3 = COLORS.BG_LIGHT,
        LayoutOrder = 2,
        Parent = riskSection,
    })
    self:_corner(barBg, 5)

    local riskPct = { NONE = 0, LOW = 0.25, MEDIUM = 0.5, HIGH = 0.75, CRITICAL = 1.0 }
    local barFill = self:_create("Frame", {
        Size = UDim2.new(riskPct[riskLevel] or 0, 0, 1, 0),
        BackgroundColor3 = riskColor,
        Parent = barBg,
    })
    self:_corner(barFill, 5)

    -- Scan Overview
    local scanSection = self:_createSection(page, "📊 Scan Overview", 2)

    local maxScripts = math.max(scanner.scripts_analyzed or 0, 1)
    self:_createStatBar(scanSection, "Scripts Analisados", scanner.scripts_analyzed or 0, maxScripts, COLORS.ACCENT, 1)
    self:_createStatBar(scanSection, "RemoteEvents", scanner.remote_events or 0, maxScripts, COLORS.MEDIUM, 2)
    self:_createStatBar(scanSection, "RemoteFunctions", scanner.remote_functions or 0, maxScripts, COLORS.MEDIUM, 3)
    self:_createStatBar(scanSection, "Itens Suspeitos", scanner.suspicious_items or 0, maxScripts, COLORS.HIGH, 4)

    -- Network Overview
    local net = data.network or {}
    local totalReqs = net.total_requests or net.total or 0
    local suspReqs = net.suspicious_requests or net.suspicious or 0
    if totalReqs > 0 or suspReqs > 0 then
        self:_createStatBar(scanSection, "Network Requests", totalReqs, math.max(totalReqs, 1), COLORS.ACCENT, 5)
        self:_createStatBar(scanSection, "Network Suspeitos", suspReqs, math.max(totalReqs, 1), COLORS.HIGH, 6)
    end

    -- Obfuscation Overview (v2 loader data)
    local obf = data.obfuscation or {}
    if obf.detected and obf.detected > 0 then
        self:_createStatBar(scanSection, "Ofuscação Detectada", obf.detected, obf.detected, COLORS.HIGH, 7)
    end

    -- Vulnerabilidades Resumo
    local vulnSection = self:_createSection(page, "🛡️ Vulnerabilidades", 3)

    self:_createStatBar(vulnSection, "⚫ CRITICAL", bySev.CRITICAL or 0, math.max(totalVuln, 1), COLORS.CRITICAL, 1)
    self:_createStatBar(vulnSection, "🔴 HIGH", bySev.HIGH or 0, math.max(totalVuln, 1), COLORS.HIGH, 2)
    self:_createStatBar(vulnSection, "🟠 MEDIUM", bySev.MEDIUM or 0, math.max(totalVuln, 1), COLORS.MEDIUM, 3)
    self:_createStatBar(vulnSection, "🟡 LOW", bySev.LOW or 0, math.max(totalVuln, 1), COLORS.LOW, 4)

    -- Heuristic Summary
    if heuristic.total_analyzed and heuristic.total_analyzed > 0 then
        local heuSection = self:_createSection(page, "🧠 Heuristic / Risk Analysis", 4)
        self:_createStatBar(heuSection, "Analisados", heuristic.total_analyzed or 0, math.max(heuristic.total_analyzed or 1, 1), COLORS.ACCENT, 1)
        self:_createStatBar(heuSection, "Score Máximo", heuristic.max_score or 0, 100, COLORS.HIGH, 2)
        self:_createStatBar(heuSection, "Score Médio", math.floor(heuristic.average_score or 0), 100, COLORS.MEDIUM, 3)
    end

    -- Performance
    local perf = data.performance or {}
    if perf.events_logged then
        local perfSection = self:_createSection(page, "⚡ Performance", 5)
        self:_createStatBar(perfSection, "Eventos Debug", perf.events_logged or 0, math.max(perf.events_logged or 1, 1), COLORS.ACCENT, 1)

        self:_create("TextLabel", {
            Size = UDim2.new(1, 0, 0, 18),
            BackgroundTransparency = 1,
            Text = "Verbose: " .. (perf.verbose_mode and "ON ✅" or "OFF"),
            TextColor3 = COLORS.TEXT_SECONDARY,
            TextSize = FONT_SIZES.SMALL,
            Font = Enum.Font.Gotham,
            TextXAlignment = Enum.TextXAlignment.Left,
            LayoutOrder = 2,
            Parent = perfSection,
        })
    end

    -- Botão copiar overview inteiro
    local overviewText = string.format(
        "=== Scanning-Lua Overview ===\nRisk Level: %s\nVulnerabilities: %d\n  CRITICAL: %d\n  HIGH: %d\n  MEDIUM: %d\n  LOW: %d\nScripts Analyzed: %d\nRemoteEvents: %d\nRemoteFunctions: %d\nSuspicious Items: %d\nNetwork Requests: %d\nNetwork Suspicious: %d\nHeuristic Max Score: %s\nHeuristic Avg Score: %s",
        riskLevel, totalVuln,
        bySev.CRITICAL or 0, bySev.HIGH or 0, bySev.MEDIUM or 0, bySev.LOW or 0,
        scanner.scripts_analyzed or 0, scanner.remote_events or 0,
        scanner.remote_functions or 0, scanner.suspicious_items or 0,
        totalReqs, suspReqs,
        tostring(heuristic.max_score or 0), string.format("%.1f", heuristic.average_score or 0)
    )

    local copyOverviewBtn = self:_create("TextButton", {
        Size = UDim2.new(1, -4, 0, 32),
        BackgroundColor3 = COLORS.ACCENT,
        Text = "📋 Copiar Overview Completo",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.BODY,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        LayoutOrder = 99,
        Parent = page,
    })
    self:_corner(copyOverviewBtn, 6)

    self:_connect(copyOverviewBtn.MouseEnter, function()
        copyOverviewBtn.BackgroundColor3 = COLORS.ACCENT_HOVER
    end)
    self:_connect(copyOverviewBtn.MouseLeave, function()
        copyOverviewBtn.BackgroundColor3 = COLORS.ACCENT
    end)
    self:_connect(copyOverviewBtn.MouseButton1Click, function()
        self:_copyToClipboard(overviewText)
        self:_flashCopy(copyOverviewBtn, COLORS.ACCENT)
    end)
end

--- Popula aba Vulnerabilidades
function ScannerGui:_populateVulns(page, data)
    local vuln = data.vulnerabilities or {}
    local details = vuln.details or vuln.vulnerabilities or {}

    if type(details) == "table" and #details > 0 then
        local order = 1
        for _, v in ipairs(details) do
            local title = string.format("[%s] %s",
                v.vuln_id or v.id or "?",
                v.name or v.type or "Unknown")
            local desc = (v.description or v.message or "") ..
                "\nCategoria: " .. (v.category or "N/A") ..
                "\nFonte: " .. (v.source or "N/A") ..
                "\nMatch: " .. (v.matched_text or v.pattern or "N/A") ..
                "\nLinha: " .. tostring(v.line_number or v.line or "N/A")
            if v.risk_score then
                desc = desc .. "\nRisk Score: " .. tostring(v.risk_score)
            end
            if v.risk_level then
                desc = desc .. "\nRisk Level: " .. v.risk_level
            end
            if v.line_content then
                desc = desc .. "\nConteúdo: " .. truncate(v.line_content, 120)
            end
            if v.remediation then
                desc = desc .. "\n\n💡 Remediação: " .. v.remediation
            end
            if v.combo_patterns then
                desc = desc .. "\nCombo: " .. table.concat(v.combo_patterns, " + ")
            end
            local sev = v.severity or "MEDIUM"

            -- Filtro de busca
            local searchable = (title .. desc):lower()
            if self.searchFilter == "" or searchable:find(self.searchFilter, 1, true) then
                self:_createResultCard(page, title, desc, sev, order)
                order = order + 1
            end
        end
    else
        self:_create("TextLabel", {
            Size = UDim2.new(1, 0, 0, 40),
            BackgroundTransparency = 1,
            Text = "✅ Nenhuma vulnerabilidade detectada",
            TextColor3 = COLORS.SUCCESS,
            TextSize = FONT_SIZES.BODY,
            Font = Enum.Font.GothamBold,
            LayoutOrder = 1,
            Parent = page,
        })
    end

    -- Botão copiar todas vulns
    local vulnText = "=== Vulnerabilidades ===\n"
    if type(details) == "table" then
        for _, v in ipairs(details) do
            vulnText = vulnText .. string.format(
                "[%s] %s — %s\n  Descrição: %s\n  Categoria: %s\n  Fonte: %s\n  Match: %s\n  Linha: %s\n  Remediação: %s\n\n",
                v.severity or "?",
                v.vuln_id or v.id or "?",
                v.name or v.type or "Unknown",
                v.description or v.message or "N/A",
                v.category or "N/A",
                v.source or "N/A",
                v.matched_text or v.pattern or "N/A",
                tostring(v.line_number or v.line or "N/A"),
                v.remediation or "N/A")
        end
    end

    local copyBtn = self:_create("TextButton", {
        Size = UDim2.new(1, -4, 0, 30),
        BackgroundColor3 = COLORS.ACCENT,
        Text = "📋 Copiar Todas Vulnerabilidades",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.SMALL,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        LayoutOrder = 9999,
        Parent = page,
    })
    self:_corner(copyBtn, 6)

    self:_connect(copyBtn.MouseEnter, function() copyBtn.BackgroundColor3 = COLORS.ACCENT_HOVER end)
    self:_connect(copyBtn.MouseLeave, function() copyBtn.BackgroundColor3 = COLORS.ACCENT end)
    self:_connect(copyBtn.MouseButton1Click, function()
        self:_copyToClipboard(vulnText)
        self:_flashCopy(copyBtn, COLORS.ACCENT)
    end)
end

--- Popula aba Heuristic
function ScannerGui:_populateHeuristic(page, data)
    local heuristic = data.heuristic or {}
    local analyses = heuristic.analyses or {}

    if type(analyses) == "table" and #analyses > 0 then
        local order = 1
        for _, a in ipairs(analyses) do
            local title = (a.source or "Unknown") .. " — Score: " .. (a.score or 0)
            local desc = "Level: " .. (a.level or "NONE")

            -- Handle both v3 format (indicators_found) and v2 format (findings)
            local indicators = a.indicators_found or a.findings or {}
            local multipliers = a.multipliers_applied or a.combos or {}

            desc = desc .. "\nIndicadores: " .. tostring(#indicators)
            desc = desc .. "\nMultiplicadores: " .. tostring(#multipliers)

            if #indicators > 0 then
                desc = desc .. "\n\nIndicadores encontrados:"
                for _, ind in ipairs(indicators) do
                    if type(ind) == "table" then
                        local indName = ind.name or ind.pattern or tostring(ind)
                        local indWeight = ind.weight or ind.effective_weight or ""
                        local indCount = ind.count or ""
                        if indWeight ~= "" then
                            desc = desc .. "\n  • " .. indName .. " (peso: " .. tostring(indWeight) .. ", count: " .. tostring(indCount) .. ")"
                        else
                            desc = desc .. "\n  • " .. indName
                        end
                    else
                        desc = desc .. "\n  • " .. tostring(ind)
                    end
                end
            end

            if #multipliers > 0 then
                desc = desc .. "\n\nMultiplicadores:"
                for _, m in ipairs(multipliers) do
                    if type(m) == "table" then
                        local mName = m.name or "Combo"
                        local mVal = m.multiplier or m.value or ""
                        desc = desc .. "\n  × " .. tostring(mName) .. " (" .. tostring(mVal) .. ")"
                    else
                        desc = desc .. "\n  × " .. tostring(m)
                    end
                end
            end

            local sev = a.level or "NONE"

            local searchable = (title .. desc):lower()
            if self.searchFilter == "" or searchable:find(self.searchFilter, 1, true) then
                self:_createResultCard(page, title, desc, sev, order)
                order = order + 1
            end
        end
    else
        self:_create("TextLabel", {
            Size = UDim2.new(1, 0, 0, 40),
            BackgroundTransparency = 1,
            Text = "Nenhuma análise heurística disponível",
            TextColor3 = COLORS.TEXT_DIM,
            TextSize = FONT_SIZES.BODY,
            Font = Enum.Font.Gotham,
            LayoutOrder = 1,
            Parent = page,
        })
    end

    -- Copiar todas análises
    local hText = "=== Heuristic Analyses ===\n"
    if type(analyses) == "table" then
        for _, a in ipairs(analyses) do
            hText = hText .. string.format("[%s] %s: score=%s level=%s\n",
                a.level or "?", a.source or "?", tostring(a.score or 0), a.level or "?")
            local indicators = a.indicators_found or a.findings or {}
            for _, ind in ipairs(indicators) do
                if type(ind) == "table" then
                    hText = hText .. string.format("  • %s (weight=%s, count=%s)\n",
                        ind.name or ind.pattern or "?",
                        tostring(ind.weight or "?"),
                        tostring(ind.count or "?"))
                end
            end
        end
    end

    local copyBtn = self:_create("TextButton", {
        Size = UDim2.new(1, -4, 0, 30),
        BackgroundColor3 = COLORS.ACCENT,
        Text = "📋 Copiar Análises Heurísticas",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.SMALL,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        LayoutOrder = 9999,
        Parent = page,
    })
    self:_corner(copyBtn, 6)

    self:_connect(copyBtn.MouseEnter, function() copyBtn.BackgroundColor3 = COLORS.ACCENT_HOVER end)
    self:_connect(copyBtn.MouseLeave, function() copyBtn.BackgroundColor3 = COLORS.ACCENT end)
    self:_connect(copyBtn.MouseButton1Click, function()
        self:_copyToClipboard(hText)
        self:_flashCopy(copyBtn, COLORS.ACCENT)
    end)
end

--- Popula aba Signatures
function ScannerGui:_populateSignatures(page, data)
    local sigs = data.signatures or {}
    local detections = sigs.detections or {}

    if type(detections) == "table" and #detections > 0 then
        local order = 1
        for _, d in ipairs(detections) do
            local title = (d.signature_id or "SIG") .. " — " .. (d.signature_name or "Unknown")
            local desc = "Fonte: " .. (d.source or "N/A") ..
                "\nLinha: " .. tostring(d.line_number or "?") ..
                "\nDescrição: " .. (d.description or "N/A") ..
                "\nMatch: " .. truncate(d.matched_text or "", 120)
            local sev = d.severity or "HIGH"

            local searchable = (title .. desc):lower()
            if self.searchFilter == "" or searchable:find(self.searchFilter, 1, true) then
                self:_createResultCard(page, title, desc, sev, order)
                order = order + 1
            end
        end
    else
        self:_create("TextLabel", {
            Size = UDim2.new(1, 0, 0, 40),
            BackgroundTransparency = 1,
            Text = "✅ Nenhuma assinatura de ameaça detectada",
            TextColor3 = COLORS.SUCCESS,
            TextSize = FONT_SIZES.BODY,
            Font = Enum.Font.GothamBold,
            LayoutOrder = 1,
            Parent = page,
        })
    end

    -- Copiar
    local sText = "=== Signature Detections ===\n"
    if type(detections) == "table" then
        for _, d in ipairs(detections) do
            sText = sText .. string.format("[%s] %s — %s (line %s) in %s\n",
                d.severity or "?", d.signature_id or "?", d.signature_name or "?",
                tostring(d.line_number or "?"), d.source or "?")
        end
    end

    local copyBtn = self:_create("TextButton", {
        Size = UDim2.new(1, -4, 0, 30),
        BackgroundColor3 = COLORS.ACCENT,
        Text = "📋 Copiar Detecções de Assinatura",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.SMALL,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        LayoutOrder = 9999,
        Parent = page,
    })
    self:_corner(copyBtn, 6)

    self:_connect(copyBtn.MouseEnter, function() copyBtn.BackgroundColor3 = COLORS.ACCENT_HOVER end)
    self:_connect(copyBtn.MouseLeave, function() copyBtn.BackgroundColor3 = COLORS.ACCENT end)
    self:_connect(copyBtn.MouseButton1Click, function()
        self:_copyToClipboard(sText)
        self:_flashCopy(copyBtn, COLORS.ACCENT)
    end)
end

--- Popula aba Network
function ScannerGui:_populateNetwork(page, data)
    local network = data.network or {}
    local requests = network.requests or network.log or {}

    -- Stats (handle both v2 and v3 field names)
    local totalReqs = network.total_requests or network.total or 0
    local suspReqs = network.suspicious_requests or network.suspicious or 0

    local statsSection = self:_createSection(page, "📡 Network Stats", 1)

    self:_createStatBar(statsSection, "Total Requests", totalReqs,
        math.max(totalReqs, 1), COLORS.ACCENT, 1)
    self:_createStatBar(statsSection, "Suspicious", suspReqs,
        math.max(totalReqs, 1), COLORS.HIGH, 2)

    if network.blocked then
        self:_createStatBar(statsSection, "Blocked", network.blocked or 0,
            math.max(totalReqs, 1), COLORS.CRITICAL, 3)
    end

    -- Detalhes de requests
    if type(requests) == "table" and #requests > 0 then
        local order = 10
        for _, r in ipairs(requests) do
            local title = (r.method or "GET") .. " " .. truncate(r.url or r.domain or "Unknown", 60)
            -- Handle both v2 format (domain_risk.risk) and v3 format (risk_score)
            local riskScore = r.risk_score or r.risk or 0
            if type(r.domain_risk) == "table" then
                riskScore = r.domain_risk.risk or riskScore
            end
            local reason = r.reason or "N/A"
            if type(r.domain_risk) == "table" and r.domain_risk.reason then
                reason = r.domain_risk.reason
            end
            local desc = "URL: " .. (r.url or "N/A") ..
                "\nDomínio: " .. (r.domain or "N/A") ..
                "\nRisco: " .. tostring(riskScore) ..
                "\nMotivo: " .. reason
            if r.is_suspicious then
                desc = desc .. "\n⚠️ Suspeito"
            end
            if r.is_burst then
                desc = desc .. "\n⚡ Burst detectado"
            end
            local sev = "NONE"
            if riskScore >= 8 then sev = "CRITICAL"
            elseif riskScore >= 6 then sev = "HIGH"
            elseif riskScore >= 4 then sev = "MEDIUM"
            elseif riskScore >= 2 then sev = "LOW" end

            local searchable = (title .. desc):lower()
            if self.searchFilter == "" or searchable:find(self.searchFilter, 1, true) then
                self:_createResultCard(page, title, desc, sev, order)
                order = order + 1
            end
        end
    else
        -- Estado vazio quando não há requisições registradas
        self:_create("TextLabel", {
            Size = UDim2.new(1, 0, 0, 40),
            BackgroundTransparency = 1,
            Text = "✅ Nenhuma requisição de rede registrada",
            TextColor3 = COLORS.SUCCESS,
            TextSize = FONT_SIZES.BODY,
            Font = Enum.Font.GothamBold,
            LayoutOrder = 11,
            Parent = page,
        })
    end

    -- Copiar
    local nText = "=== Network Monitor ===\n"
    nText = nText .. string.format("Total: %d, Suspicious: %d\n\n",
        totalReqs, suspReqs)
    if type(requests) == "table" then
        for _, r in ipairs(requests) do
            local riskScore = r.risk_score or r.risk or 0
            if type(r.domain_risk) == "table" then
                riskScore = r.domain_risk.risk or riskScore
            end
            local reason = r.reason or ""
            if type(r.domain_risk) == "table" and r.domain_risk.reason then
                reason = r.domain_risk.reason
            end
            nText = nText .. string.format("[Risk:%s] %s %s — %s\n",
                tostring(riskScore), r.method or "?",
                r.url or "?", reason)
        end
    end

    local copyBtn = self:_create("TextButton", {
        Size = UDim2.new(1, -4, 0, 30),
        BackgroundColor3 = COLORS.ACCENT,
        Text = "📋 Copiar Dados de Rede",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.SMALL,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        LayoutOrder = 9999,
        Parent = page,
    })
    self:_corner(copyBtn, 6)

    self:_connect(copyBtn.MouseEnter, function() copyBtn.BackgroundColor3 = COLORS.ACCENT_HOVER end)
    self:_connect(copyBtn.MouseLeave, function() copyBtn.BackgroundColor3 = COLORS.ACCENT end)
    self:_connect(copyBtn.MouseButton1Click, function()
        self:_copyToClipboard(nText)
        self:_flashCopy(copyBtn, COLORS.ACCENT)
    end)
end

--- Popula aba Advanced (advanced_detector scan history)
function ScannerGui:_populateAdvanced(page, data)
    local adv = data.advanced or {}
    local history = adv.scan_history or {}

    -- Resumo estatístico
    local statsSection = self:_createSection(page, "🔬 Advanced Detection Stats", 1)
    local totalScanned = adv.total_scanned or 0
    local totalFindings = adv.total_findings or 0
    self:_createStatBar(statsSection, "Scripts Escaneados", totalScanned, math.max(totalScanned, 1), COLORS.ACCENT, 1)
    self:_createStatBar(statsSection, "Findings Total", totalFindings, math.max(totalFindings, 1), COLORS.HIGH, 2)
    self:_createStatBar(statsSection, "Combos Detectados", adv.combos_detected or 0, math.max(totalFindings, 1), COLORS.CRITICAL, 3)
    self:_createStatBar(statsSection, "URLs Suspeitas", adv.urls_detected or 0, math.max(totalFindings, 1), COLORS.MEDIUM, 4)
    self:_createStatBar(statsSection, "Anti-Debug", adv.anti_debug_detected or 0, math.max(totalFindings, 1), COLORS.MEDIUM, 5)

    local bySev = adv.by_severity or {}
    self:_createStatBar(statsSection, "⚫ CRITICAL", bySev.CRITICAL or 0, math.max(totalFindings, 1), COLORS.CRITICAL, 6)
    self:_createStatBar(statsSection, "🔴 HIGH", bySev.HIGH or 0, math.max(totalFindings, 1), COLORS.HIGH, 7)
    self:_createStatBar(statsSection, "🟠 MEDIUM", bySev.MEDIUM or 0, math.max(totalFindings, 1), COLORS.MEDIUM, 8)
    self:_createStatBar(statsSection, "🟡 LOW", bySev.LOW or 0, math.max(totalFindings, 1), COLORS.LOW, 9)

    -- Histórico de scans individuais
    if type(history) == "table" and #history > 0 then
        local order = 10
        for _, scan in ipairs(history) do
            local title = (scan.script or "Unknown") .. " — Score: " .. tostring(scan.score or 0)
            local sev = scan.risk or "NONE"

            local desc = "Risk: " .. sev ..
                "\nFindings: " .. tostring(scan.finding_count or #(scan.findings or {})) ..
                "\nCombos: " .. tostring(scan.combo_count or #(scan.combos or {})) ..
                "\nObfuscation score: " .. tostring(scan.obfuscation and scan.obfuscation.score or 0)

            if scan.combos and #scan.combos > 0 then
                desc = desc .. "\n\nCombos:"
                for _, c in ipairs(scan.combos) do
                    desc = desc .. "\n  💥 " .. (c.name or "?") .. " — " .. (c.attack or "")
                end
            end

            if scan.findings and #scan.findings > 0 then
                desc = desc .. "\n\nFindings:"
                for _, f in ipairs(scan.findings) do
                    local lineNum = f.line or 0
                    if lineNum > 0 then
                        desc = desc .. string.format("\n  💣 L%d [%s] %s → %s",
                            lineNum, f.risk or "?", f.reason or "?", f.attack or "?")
                    else
                        desc = desc .. string.format("\n  💣 [%s] %s → %s",
                            f.risk or "?", f.reason or "?", f.attack or "?")
                    end
                end
            end

            if scan.urls and type(scan.urls.suspicious) == "table" and #scan.urls.suspicious > 0 then
                desc = desc .. "\n\nURLs suspeitas:"
                for _, u in ipairs(scan.urls.suspicious) do
                    desc = desc .. "\n  🌐 " .. (u.reason or u.pattern or "?")
                end
            end

            if scan.anti_debug and #scan.anti_debug > 0 then
                desc = desc .. "\n\nAnti-debug:"
                for _, ad in ipairs(scan.anti_debug) do
                    desc = desc .. "\n  🧪 " .. (ad.name or "?")
                end
            end

            local searchable = (title .. desc):lower()
            if self.searchFilter == "" or searchable:find(self.searchFilter, 1, true) then
                self:_createResultCard(page, title, desc, sev, order)
                order = order + 1
            end
        end
    else
        self:_create("TextLabel", {
            Size = UDim2.new(1, 0, 0, 40),
            BackgroundTransparency = 1,
            Text = "Nenhum scan avançado disponível",
            TextColor3 = COLORS.TEXT_DIM,
            TextSize = FONT_SIZES.BODY,
            Font = Enum.Font.Gotham,
            LayoutOrder = 11,
            Parent = page,
        })
    end

    -- Copiar
    local advText = "=== Advanced Detection ===\n"
    advText = advText .. string.format("Total scanned: %d | Findings: %d | Combos: %d\n\n",
        adv.total_scanned or 0, adv.total_findings or 0, adv.combos_detected or 0)
    if type(history) == "table" then
        for _, scan in ipairs(history) do
            advText = advText .. string.format("[%s] %s: score=%d (%s) | %d findings | %d combos\n",
                scan.risk or "?", scan.script or "?", scan.score or 0, scan.risk or "?",
                scan.finding_count or #(scan.findings or {}),
                scan.combo_count or #(scan.combos or {}))
        end
    end

    local copyBtn = self:_create("TextButton", {
        Size = UDim2.new(1, -4, 0, 30),
        BackgroundColor3 = COLORS.ACCENT,
        Text = "📋 Copiar Detecções Avançadas",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.SMALL,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        LayoutOrder = 9999,
        Parent = page,
    })
    self:_corner(copyBtn, 6)

    self:_connect(copyBtn.MouseEnter, function() copyBtn.BackgroundColor3 = COLORS.ACCENT_HOVER end)
    self:_connect(copyBtn.MouseLeave, function() copyBtn.BackgroundColor3 = COLORS.ACCENT end)
    self:_connect(copyBtn.MouseButton1Click, function()
        self:_copyToClipboard(advText)
        self:_flashCopy(copyBtn, COLORS.ACCENT)
    end)
end

--- Popula aba Resultados (todos os retornos)
function ScannerGui:_populateResults(page, data)
    local order = 1

    -- Seção: Log Entries (mostrar logs do scanner na GUI)
    local logEntries = data.log_entries or {}
    if type(logEntries) == "table" and #logEntries > 0 then
        local logsSection = self:_createSection(page, "📝 Logs do Scanner", 1)
        local logOrder = 1

        local logLevelEmojis = {
            CRITICAL = "⚫",
            ERROR = "🔴",
            WARN = "🟠",
            INFO = "🔵",
            DEBUG = "⚪",
        }

        local logLevelToSeverity = {
            CRITICAL = "CRITICAL",
            ERROR = "HIGH",
            WARN = "MEDIUM",
            INFO = "NONE",
            DEBUG = "NONE",
        }

        -- Mostrar logs do mais recente para o mais antigo (limitar a 100 entradas)
        local maxLogDisplay = 100
        local startIdx = math.max(1, #logEntries - maxLogDisplay + 1)
        for i = #logEntries, startIdx, -1 do
            local entry = logEntries[i]
            if type(entry) == "table" then
                local lvl = entry.level or "INFO"
                local emoji = logLevelEmojis[lvl] or "⚪"
                local logTitle = string.format("%s [%s] %s", emoji, lvl, entry.category or "")
                local logDesc = (entry.message or "") ..
                    "\nTimestamp: " .. (entry.timestamp or "N/A")
                if entry.data then
                    logDesc = logDesc .. "\nDados: " .. safeTostring(entry.data)
                end
                if entry.stacktrace then
                    logDesc = logDesc .. "\n\nStack trace:\n" .. tostring(entry.stacktrace)
                end

                local searchable = (logTitle .. logDesc):lower()
                if self.searchFilter == "" or searchable:find(self.searchFilter, 1, true) then
                    local cardSev = logLevelToSeverity[lvl] or "NONE"

                    self:_createResultCard(logsSection, logTitle, logDesc, cardSev, logOrder)
                    logOrder = logOrder + 1
                end
            end
        end

        -- Botão copiar todos os logs
        local logsText = "=== Scanning-Lua Logs ===\n"
        for _, entry in ipairs(logEntries) do
            if type(entry) == "table" then
                logsText = logsText .. string.format("[%s][%s][%s] %s\n",
                    entry.timestamp or "?", entry.level or "?",
                    entry.category or "?", entry.message or "")
            end
        end

        local copyLogsBtn = self:_create("TextButton", {
            Size = UDim2.new(1, -4, 0, 30),
            BackgroundColor3 = COLORS.ACCENT,
            Text = "📋 Copiar Todos os Logs",
            TextColor3 = COLORS.TEXT_PRIMARY,
            TextSize = FONT_SIZES.SMALL,
            Font = Enum.Font.GothamBold,
            AutoButtonColor = false,
            LayoutOrder = logOrder + 1,
            Parent = logsSection,
        })
        self:_corner(copyLogsBtn, 6)

        self:_connect(copyLogsBtn.MouseEnter, function() copyLogsBtn.BackgroundColor3 = COLORS.ACCENT_HOVER end)
        self:_connect(copyLogsBtn.MouseLeave, function() copyLogsBtn.BackgroundColor3 = COLORS.ACCENT end)
        self:_connect(copyLogsBtn.MouseButton1Click, function()
            self:_copyToClipboard(logsText)
            self:_flashCopy(copyLogsBtn, COLORS.ACCENT)
        end)
    end

    -- Seção: Estatísticas completas
    local statsSection = self:_createSection(page, "📊 Estatísticas Completas", 2)

    -- Listar todas as chaves de data como resultados copiáveis (excluir log_entries que já é exibido acima)
    local allKeys = {}
    for k in pairs(data) do
        if k ~= "log_entries" then
            allKeys[#allKeys + 1] = k
        end
    end
    table.sort(allKeys)

    for _, key in ipairs(allKeys) do
        local val = data[key]
        local valStr = safeTostring(val)
        if type(val) == "table" then
            -- Expandir tabela em sub-campos
            local subParts = {}
            for sk, sv in pairs(val) do
                subParts[#subParts + 1] = "  " .. tostring(sk) .. ": " .. safeTostring(sv)
            end
            table.sort(subParts)
            valStr = table.concat(subParts, "\n")
        end

        local searchable = (key .. valStr):lower()
        if self.searchFilter == "" or searchable:find(self.searchFilter, 1, true) then
            order = order + 1

            local row = self:_create("Frame", {
                Size = UDim2.new(1, -4, 0, 0),
                AutomaticSize = Enum.AutomaticSize.Y,
                BackgroundColor3 = COLORS.BG_CARD,
                LayoutOrder = order,
                Parent = statsSection,
            })
            self:_corner(row, 6)
            self:_padding(row, 6, 8, 6, 8)
            self:_listLayout(row, 3)

            -- Header com key e botão copiar
            local hdr = self:_create("Frame", {
                Size = UDim2.new(1, 0, 0, 20),
                BackgroundTransparency = 1,
                LayoutOrder = 1,
                Parent = row,
            })

            self:_create("TextLabel", {
                Size = UDim2.new(1, -70, 1, 0),
                BackgroundTransparency = 1,
                Text = "📁 " .. key,
                TextColor3 = COLORS.ACCENT,
                TextSize = FONT_SIZES.BODY,
                Font = Enum.Font.GothamBold,
                TextXAlignment = Enum.TextXAlignment.Left,
                Parent = hdr,
            })

            local copyText = key .. ":\n" .. valStr
            local btn = self:_create("TextButton", {
                Size = UDim2.new(0, 60, 0, 18),
                Position = UDim2.new(1, -60, 0, 1),
                BackgroundColor3 = COLORS.BTN_COPY,
                Text = "📋 Copy",
                TextColor3 = COLORS.TEXT_PRIMARY,
                TextSize = FONT_SIZES.TINY,
                Font = Enum.Font.GothamMedium,
                AutoButtonColor = false,
                Parent = hdr,
            })
            self:_corner(btn, 4)

            self:_connect(btn.MouseEnter, function() btn.BackgroundColor3 = COLORS.BTN_COPY_HOVER end)
            self:_connect(btn.MouseLeave, function() btn.BackgroundColor3 = COLORS.BTN_COPY end)
            self:_connect(btn.MouseButton1Click, function()
                self:_copyToClipboard(copyText)
                self:_flashCopy(btn, COLORS.BTN_COPY)
            end)

            -- Valor
            self:_create("TextLabel", {
                Size = UDim2.new(1, 0, 0, 0),
                AutomaticSize = Enum.AutomaticSize.Y,
                BackgroundTransparency = 1,
                Text = truncate(valStr, 500),
                TextColor3 = COLORS.TEXT_SECONDARY,
                TextSize = FONT_SIZES.SMALL,
                Font = Enum.Font.Gotham,
                TextXAlignment = Enum.TextXAlignment.Left,
                TextWrapped = true,
                LayoutOrder = 2,
                Parent = row,
            })
        end
    end

    -- Copiar tudo (JSON-like)
    local allText = "=== Scanning-Lua Full Results ===\n"
    for _, key in ipairs(allKeys) do
        allText = allText .. "\n[" .. key .. "]\n" .. safeTostring(data[key]) .. "\n"
    end

    local copyAllBtn = self:_create("TextButton", {
        Size = UDim2.new(1, -4, 0, 34),
        BackgroundColor3 = COLORS.ACCENT,
        Text = "📋 Copiar TODOS os Resultados",
        TextColor3 = COLORS.TEXT_PRIMARY,
        TextSize = FONT_SIZES.BODY,
        Font = Enum.Font.GothamBold,
        AutoButtonColor = false,
        LayoutOrder = 9999,
        Parent = page,
    })
    self:_corner(copyAllBtn, 6)

    self:_connect(copyAllBtn.MouseEnter, function() copyAllBtn.BackgroundColor3 = COLORS.ACCENT_HOVER end)
    self:_connect(copyAllBtn.MouseLeave, function() copyAllBtn.BackgroundColor3 = COLORS.ACCENT end)
    self:_connect(copyAllBtn.MouseButton1Click, function()
        self:_copyToClipboard(allText)
        self:_flashCopy(copyAllBtn, COLORS.ACCENT)
    end)
end

-- ============================================================
-- Controles da GUI
-- ============================================================

--- Atualiza a GUI com novos resultados
--- @param results table Resultados do scan (output de getStats, scanCode, etc.)
function ScannerGui:update(results)
    if type(results) ~= "table" then
        results = buildDefaultResults()
    end

    self.lastResults = results

    if not self.gui or not self.isVisible then return end

    -- Popular a aba atual imediatamente
    if self.currentTab and self.tabPages[self.currentTab] then
        self:populateTab(self.currentTab, results)
    end
end

--- Mostra a GUI
function ScannerGui:show()
    if not self.gui then
        self:build()
    end
    self.gui.Enabled = true
    self.isVisible = true
    if self.lastResults then
        self:update(self.lastResults)
    else
        -- Show empty state so GUI is not completely blank
        self:update(buildDefaultResults())
    end
end

--- Esconde a GUI
function ScannerGui:hide()
    if self.gui then
        self.gui.Enabled = false
    end
    self.isVisible = false
end

--- Toggle visibilidade
function ScannerGui:toggle()
    if self.isVisible then
        self:hide()
    else
        self:show()
    end
end

--- Minimiza/restaura a janela
function ScannerGui:toggleMinimize()
    if not self.mainFrame or not self.contentFrame then return end
    self.isMinimized = not self.isMinimized

    if self.isMinimized then
        self.contentFrame.Visible = false
        self.mainFrame.Size = UDim2.new(0, 580, 0, 40)
    else
        self.contentFrame.Visible = true
        self.mainFrame.Size = UDim2.new(0, 580, 0, 480)
    end
end

--- Copia todos os resultados para clipboard
function ScannerGui:copyAllResults()
    if not self.lastResults then return end

    local text = "=== Scanning-Lua v3.0.0 — Full Report ===\n"
    text = text .. "Generated: " .. os.date("!%Y-%m-%d %H:%M:%S UTC") .. "\n\n"

    local function appendTable(t, prefix)
        prefix = prefix or ""
        for k, v in pairs(t) do
            if type(v) == "table" then
                text = text .. prefix .. tostring(k) .. ":\n"
                appendTable(v, prefix .. "  ")
            else
                text = text .. prefix .. tostring(k) .. ": " .. tostring(v) .. "\n"
            end
        end
    end

    appendTable(self.lastResults)

    self:_copyToClipboard(text)
end

--- Destrói a GUI e limpa connections
function ScannerGui:destroy()
    for _, conn in ipairs(self.connections) do
        pcall(function() conn:Disconnect() end)
    end
    self.connections = {}

    if self.gui then
        pcall(function() self.gui:Destroy() end)
        self.gui = nil
    end

    self.mainFrame = nil
    self.contentFrame = nil
    self.tabs = {}
    self.tabPages = {}
    self.isVisible = false
    self.isMinimized = false
end

return ScannerGui
