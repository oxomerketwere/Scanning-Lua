--[[
    Scanning-Lua - Thread Controller Module (#16)
    Controle de threads para evitar travar jogos grandes

    Features:
    - Limite de tasks simultâneas
    - Fila de processamento (task queue)
    - Yield entre operações pesadas
    - Controle de taxa de execução
]]

local ThreadController = {}
ThreadController.__index = ThreadController

--- Cria uma nova instância do controlador de threads
--- @param config table Configurações
--- @param logger table Instância do Logger
--- @return table ThreadController instance
function ThreadController.new(config, logger)
    local self = setmetatable({}, ThreadController)
    self.config = config or {}
    self.logger = logger

    -- Configurações de controle
    self.maxConcurrent = config.MAX_CONCURRENT_TASKS or 3
    self.yieldInterval = config.YIELD_INTERVAL or 10       -- Yield a cada N operações
    self.yieldDuration = config.YIELD_DURATION or 0.03     -- Duração do yield (segundos)
    self.batchSize = config.BATCH_SIZE or 20               -- Tamanho do lote de processamento

    -- Estado
    self.queue = {}
    self.activeTasks = 0
    self.operationCount = 0
    self.isProcessing = false
    self.stats = {
        total_queued = 0,
        total_processed = 0,
        total_yields = 0,
        max_concurrent_reached = 0,
        average_batch_time = 0,
    }

    return self
end

--- Adiciona uma tarefa à fila de processamento
--- @param taskFn function Função a executar
--- @param priority number|nil Prioridade (maior = mais urgente, padrão 0)
--- @param name string|nil Nome da tarefa (para logging)
--- @return number Posição na fila
function ThreadController:enqueue(taskFn, priority, name)
    local task = {
        fn = taskFn,
        priority = priority or 0,
        name = name or "task_" .. (#self.queue + 1),
        queued_at = os.time(),
    }

    -- Inserir na posição correta por prioridade
    local inserted = false
    for i = 1, #self.queue do
        if task.priority > self.queue[i].priority then
            table.insert(self.queue, i, task)
            inserted = true
            break
        end
    end
    if not inserted then
        self.queue[#self.queue + 1] = task
    end

    self.stats.total_queued = self.stats.total_queued + 1

    if self.logger then
        self.logger:debug("THREAD", string.format(
            "Tarefa enfileirada: %s (prioridade: %d, fila: %d)",
            task.name, task.priority, #self.queue
        ))
    end

    return #self.queue
end

--- Processa a fila de tarefas com controle de concorrência
--- @param callback function|nil Callback quando todas as tarefas forem processadas
function ThreadController:processQueue(callback)
    if self.isProcessing then
        if self.logger then
            self.logger:warn("THREAD", "Fila já está sendo processada")
        end
        return
    end

    self.isProcessing = true

    if self.logger then
        self.logger:info("THREAD", string.format(
            "Iniciando processamento: %d tarefas na fila", #self.queue
        ))
    end

    -- Tentar usar task.defer se disponível (ambiente Roblox)
    local hasTaskLib = false
    pcall(function() hasTaskLib = task and task.defer ~= nil end)

    if hasTaskLib then
        self:_processAsync(callback)
    else
        self:_processSync(callback)
    end
end

--- Processamento assíncrono (Roblox com task library)
function ThreadController:_processAsync(callback)
    local selfRef = self

    task.defer(function()
        while #selfRef.queue > 0 do
            -- Esperar se atingiu limite de concorrência
            while selfRef.activeTasks >= selfRef.maxConcurrent do
                task.wait(selfRef.yieldDuration)
            end

            -- Pegar próxima tarefa
            local nextTask = table.remove(selfRef.queue, 1)
            if not nextTask then break end

            selfRef.activeTasks = selfRef.activeTasks + 1
            if selfRef.activeTasks > selfRef.stats.max_concurrent_reached then
                selfRef.stats.max_concurrent_reached = selfRef.activeTasks
            end

            -- Executar tarefa
            task.defer(function()
                local success, err = pcall(nextTask.fn)
                selfRef.activeTasks = selfRef.activeTasks - 1
                selfRef.stats.total_processed = selfRef.stats.total_processed + 1

                if not success and selfRef.logger then
                    selfRef.logger:error("THREAD", string.format(
                        "Tarefa '%s' falhou: %s", nextTask.name, tostring(err)
                    ))
                end
            end)

            -- Yield periódico
            selfRef:_yieldIfNeeded()
        end

        -- Esperar todas as tarefas ativas terminarem
        while selfRef.activeTasks > 0 do
            task.wait(selfRef.yieldDuration)
        end

        selfRef.isProcessing = false

        if selfRef.logger then
            selfRef.logger:info("THREAD", "Processamento de fila concluído", selfRef:getStats())
        end

        if callback then callback() end
    end)
end

--- Processamento síncrono (fora do Roblox)
function ThreadController:_processSync(callback)
    local startTime = os.clock()

    while #self.queue > 0 do
        local nextTask = table.remove(self.queue, 1)
        if not nextTask then break end

        self.activeTasks = self.activeTasks + 1
        if self.activeTasks > self.stats.max_concurrent_reached then
            self.stats.max_concurrent_reached = self.activeTasks
        end

        local success, err = pcall(nextTask.fn)
        self.activeTasks = self.activeTasks - 1
        self.stats.total_processed = self.stats.total_processed + 1

        if not success and self.logger then
            self.logger:error("THREAD", string.format(
                "Tarefa '%s' falhou: %s", nextTask.name, tostring(err)
            ))
        end

        -- Simular yield com verificação de tempo
        self:_yieldIfNeeded()
    end

    self.isProcessing = false

    local elapsed = os.clock() - startTime
    self.stats.average_batch_time = elapsed

    if self.logger then
        self.logger:info("THREAD", string.format(
            "Processamento concluído em %.3fs", elapsed
        ), self:getStats())
    end

    if callback then callback() end
end

--- Yield periódico para não travar o jogo
function ThreadController:_yieldIfNeeded()
    self.operationCount = self.operationCount + 1

    if self.operationCount >= self.yieldInterval then
        self.operationCount = 0
        self.stats.total_yields = self.stats.total_yields + 1

        -- Usar task.wait se disponível, senão apenas resetar o contador
        pcall(function()
            if task and task.wait then
                task.wait(self.yieldDuration)
            end
        end)
    end
end

--- Executa uma função com yield automático a cada N iterações
--- Útil para loops sobre muitos itens
--- @param items table Array de itens a processar
--- @param processFn function Função de processamento (recebe item, índice)
--- @param batchCallback function|nil Callback ao final de cada lote
function ThreadController:processBatch(items, processFn, batchCallback)
    if type(items) ~= "table" then return end

    local total = #items
    local processed = 0

    for i = 1, total do
        local success, err = pcall(processFn, items[i], i)
        processed = processed + 1

        if not success and self.logger then
            self.logger:error("THREAD", string.format(
                "Erro processando item %d/%d: %s", i, total, tostring(err)
            ))
        end

        -- Yield a cada batchSize itens
        if processed >= self.batchSize then
            processed = 0
            self:_yieldIfNeeded()

            if batchCallback then
                batchCallback(i, total)
            end
        end
    end
end

--- Retorna tamanho atual da fila
--- @return number
function ThreadController:getQueueSize()
    return #self.queue
end

--- Retorna número de tarefas ativas
--- @return number
function ThreadController:getActiveTasks()
    return self.activeTasks
end

--- Limpa a fila
function ThreadController:clearQueue()
    local count = #self.queue
    self.queue = {}

    if self.logger then
        self.logger:info("THREAD", string.format(
            "Fila limpa: %d tarefas removidas", count
        ))
    end
end

--- Retorna estatísticas
--- @return table
function ThreadController:getStats()
    return {
        queue_size = #self.queue,
        active_tasks = self.activeTasks,
        total_queued = self.stats.total_queued,
        total_processed = self.stats.total_processed,
        total_yields = self.stats.total_yields,
        max_concurrent_reached = self.stats.max_concurrent_reached,
        is_processing = self.isProcessing,
    }
end

--- Limpa tudo
function ThreadController:reset()
    self.queue = {}
    self.activeTasks = 0
    self.operationCount = 0
    self.isProcessing = false
    self.stats = {
        total_queued = 0,
        total_processed = 0,
        total_yields = 0,
        max_concurrent_reached = 0,
        average_batch_time = 0,
    }
end

return ThreadController
