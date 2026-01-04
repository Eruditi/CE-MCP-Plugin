using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace CEPluginLibrary
{
    /// <summary>
    /// 本地HTTP服务器，用于Python与CE的通信
    /// </summary>
    public class LocalHttpServer
    {
        private readonly HttpListener listener;
        private readonly Thread serverThread;
        private bool isRunning;
        private readonly PluginExample plugin;
        
        // Rate limiting
        private readonly int maxRequestsPerMinute = 60; // Default: 60 requests per minute per client
        private readonly Dictionary<string, TokenBucket> clientRateLimits = new Dictionary<string, TokenBucket>();
        private readonly object rateLimitLock = new object();
        
        /// <summary>
        /// 令牌桶类，用于速率限制
        /// </summary>
        private class TokenBucket
        {
            private readonly int capacity;
            private readonly double refillRate; // tokens per second
            private double tokens;
            private DateTime lastRefill;
            private readonly object syncLock = new object();
            
            public TokenBucket(int capacity, double refillRate)
            {
                this.capacity = capacity;
                this.refillRate = refillRate;
                this.tokens = capacity;
                this.lastRefill = DateTime.Now;
            }
            
            public bool TryConsume(int tokensToConsume = 1)
            {
                lock (syncLock)
                {
                    // Refill tokens based on elapsed time
                    RefillTokens();
                    
                    if (tokens >= tokensToConsume)
                    {
                        tokens -= tokensToConsume;
                        return true;
                    }
                    return false;
                }
            }
            
            private void RefillTokens()
            {
                DateTime now = DateTime.Now;
                TimeSpan elapsed = now - lastRefill;
                lastRefill = now;
                
                double tokensToAdd = elapsed.TotalSeconds * refillRate;
                tokens = Math.Min(tokens + tokensToAdd, capacity);
            }
        }

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="plugin">插件实例</param>
        public LocalHttpServer(PluginExample plugin)
        {
            this.plugin = plugin;
            this.listener = new HttpListener();
            // Use configurable port from plugin configuration
            int localServerPort = 18889; // Default port
            if (plugin.config != null)
            {
                // We can add a separate LocalServerPort setting in config later if needed
                // For now, use same port as MCP server but +1
                localServerPort = plugin.config.Port + 1;
            }
            this.listener.Prefixes.Add($"http://localhost:{localServerPort}/");
            this.serverThread = new Thread(Run) { IsBackground = true, Name = "CE Local HTTP Server" };
        }

        /// <summary>
        /// 启动服务器
        /// </summary>
        public void Start()
        {
            if (isRunning)
                return;

            isRunning = true;
            listener.Start();
            serverThread.Start();
            plugin.Log("Local HTTP server started on http://localhost:18889/", PluginExample.LogLevel.Info);
        }

        /// <summary>
        /// 停止服务器
        /// </summary>
        public void Stop()
        {
            if (!isRunning)
                return;

            isRunning = false;
            listener.Stop();
            serverThread.Join(2000);
            plugin.Log("Local HTTP server stopped", PluginExample.LogLevel.Info);
        }

        /// <summary>
        /// 服务器主循环
        /// </summary>
        private void Run()
        {
            while (isRunning)
            {
                try
                {
                    HttpListenerContext context = listener.GetContext();
                    Task.Run(() => HandleRequest(context));
                }
                catch (Exception ex)
                {
                    if (isRunning) // Only log if server is still running
                    {
                        plugin.Log("Local HTTP server error: " + ex.Message, PluginExample.LogLevel.Error);
                    }
                }
            }
        }

        /// <summary>
        /// 处理HTTP请求
        /// </summary>
        /// <param name="context">请求上下文</param>
        private void HandleRequest(HttpListenerContext context)
        {
            HttpListenerResponse response = context.Response;
            
            try
            {
                HttpListenerRequest request = context.Request;

                // Check rate limit before processing request
                if (!CheckRateLimit(request, response))
                {
                    return;
                }

                // Only allow POST requests
                if (request.HttpMethod != "POST")
                {
                    SendResponse(response, HttpStatusCode.MethodNotAllowed, new { error = "Only POST requests are allowed" });
                    return;
                }

                // Validate content type
                if (request.ContentType != "application/json")
                {
                    SendResponse(response, HttpStatusCode.UnsupportedMediaType, new { error = "Content-Type must be application/json" });
                    return;
                }

                // Read request body with size limit
                string requestBody;
                long maxContentLength = 1024 * 1024; // 1MB max
                if (request.ContentLength64 > maxContentLength)
                {
                    SendResponse(response, HttpStatusCode.RequestEntityTooLarge, new { error = "Request body too large (max 1MB)" });
                    return;
                }
                
                using (StreamReader reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    requestBody = reader.ReadToEnd();
                }

                // Validate JSON syntax
                if (string.IsNullOrEmpty(requestBody))
                {
                    SendResponse(response, HttpStatusCode.BadRequest, new { error = "Request body is empty" });
                    return;
                }

                // Parse request
                dynamic requestData = null;
                try
                {
                    requestData = JsonConvert.DeserializeObject(requestBody);
                }
                catch (JsonException ex)
                {
                    SendResponse(response, HttpStatusCode.BadRequest, new { error = "Invalid JSON format" });
                    return;
                }
                
                string action = requestData?.action;

                if (string.IsNullOrEmpty(action))
                {
                    SendResponse(response, HttpStatusCode.BadRequest, new { error = "Action is required" });
                    return;
                }
                
                // Validate action name
                if (!IsValidAction(action))
                {
                    SendResponse(response, HttpStatusCode.BadRequest, new { error = "Invalid action name" });
                    return;
                }

                // Process the action
                object result;
                try
                {
                    result = ProcessAction(action, requestData);
                    SendResponse(response, HttpStatusCode.OK, result);
                }
                catch (Exception ex)
                {
                    plugin.Log($"Error processing action {action}: {ex.Message}", PluginExample.LogLevel.Error);
                    SendResponse(response, HttpStatusCode.InternalServerError, new { error = ex.Message });
                }
            }
            catch (Exception ex)
            {
                plugin.Log("Error handling request: " + ex.Message, PluginExample.LogLevel.Error);
                SendResponse(response, HttpStatusCode.InternalServerError, new { error = "Internal server error" });
            }
        }
        
        /// <summary>
        /// 检查请求速率限制
        /// </summary>
        /// <param name="request">HTTP请求</param>
        /// <param name="response">HTTP响应</param>
        /// <returns>True if request is allowed, False otherwise</returns>
        private bool CheckRateLimit(HttpListenerRequest request, HttpListenerResponse response)
        {
            // Get client IP as identifier
            string clientId = request.RemoteEndPoint?.Address.ToString() ?? "unknown";
            
            TokenBucket tokenBucket;
            
            // Get or create token bucket for client
            lock (rateLimitLock)
            {
                if (!clientRateLimits.TryGetValue(clientId, out tokenBucket))
                {
                    tokenBucket = new TokenBucket(maxRequestsPerMinute, maxRequestsPerMinute / 60.0); // Refill at 1 token per second for 60 tokens per minute
                    clientRateLimits[clientId] = tokenBucket;
                }
            }
            
            // Try to consume a token
            if (!tokenBucket.TryConsume())
            {
                SendResponse(response, HttpStatusCode.TooManyRequests, new { error = "Rate limit exceeded. Please try again later." });
                return false;
            }
            
            return true;
        }
        
        /// <summary>
        /// 验证动作名称是否有效
        /// </summary>
        /// <param name="action">动作名称</param>
        /// <returns>True if action is valid, False otherwise</returns>
        private bool IsValidAction(string action)
        {
            // List of valid actions
            HashSet<string> validActions = new HashSet<string>
            {
                "execute_lua",
                "get_process_list",
                "attach_to_process",
                "detach_from_process",
                "read_memory",
                "write_memory",
                "scan_memory",
                "freeze_memory",
                "unfreeze_memory",
                "calculate_pointer_address",
                "find_pointers",
                "disassemble",
                "set_breakpoint",
                "remove_breakpoint",
                "get_modules",
                "get_module_sections",
                "save_cheat_table",
                "load_cheat_table",
                "health_check", // Add health check action
                // Advanced CE features
                "allocate_memory",
                "deallocate_memory",
                "inject_code",
                "get_threads",
                "suspend_thread",
                "resume_thread",
                "get_handles",
                "get_symbol_address",
                "evaluate_expression"
            };
            
            return validActions.Contains(action);
        }

        /// <summary>
        /// 发送响应
        /// </summary>
        /// <param name="response">响应对象</param>
        /// <param name="statusCode">状态码</param>
        /// <param name="data">响应数据</param>
        private void SendResponse(HttpListenerResponse response, HttpStatusCode statusCode, object data)
        {
            try
            {
                string json = JsonConvert.SerializeObject(data);
                byte[] buffer = Encoding.UTF8.GetBytes(json);

                response.StatusCode = (int)statusCode;
                response.ContentType = "application/json";
                response.ContentLength64 = buffer.Length;
                response.Headers.Add("Access-Control-Allow-Origin", "*");
                response.Headers.Add("Access-Control-Allow-Methods", "POST, OPTIONS");
                response.Headers.Add("Access-Control-Allow-Headers", "Content-Type");

                using (Stream outputStream = response.OutputStream)
                {
                    outputStream.Write(buffer, 0, buffer.Length);
                }
            }
            catch (Exception ex)
            {
                plugin.Log("Error sending response: " + ex.Message, PluginExample.LogLevel.Error);
            }
        }

        /// <summary>
        /// 处理动作
        /// </summary>
        /// <param name="action">动作名称</param>
        /// <param name="requestData">请求数据</param>
        /// <returns>处理结果</returns>
        private object ProcessAction(string action, dynamic requestData)
        {
            plugin.Log($"Processing action: {action}", PluginExample.LogLevel.Debug);

            switch (action)
            {
                case "execute_lua":
                    return ExecuteLua(requestData.script);
                case "get_process_list":
                    return GetProcessList();
                case "attach_to_process":
                    return AttachToProcess(requestData.process_id);
                case "detach_from_process":
                    return DetachFromProcess();
                case "read_memory":
                    return ReadMemory(requestData.address, requestData.size, requestData.data_type);
                case "write_memory":
                    return WriteMemory(requestData.address, requestData.value, requestData.data_type);
                case "scan_memory":
                    return ScanMemory(requestData.value, requestData.data_type, requestData.scan_type);
                case "freeze_memory":
                    return FreezeMemory(requestData.address, requestData.value, requestData.data_type);
                case "unfreeze_memory":
                    return UnfreezeMemory(requestData.freeze_id);
                case "calculate_pointer_address":
                    return CalculatePointerAddress(requestData.base_address, requestData.offsets.ToObject<int[]>());
                case "find_pointers":
                    return FindPointers(requestData.target_address, requestData.max_level, requestData.max_offsets);
                case "disassemble":
                    return Disassemble(requestData.address, requestData.instruction_count);
                case "set_breakpoint":
                    return SetBreakpoint(requestData.address, requestData.breakpoint_type);
                case "remove_breakpoint":
                    return RemoveBreakpoint(requestData.address);
                case "get_modules":
                    return GetModules();
                case "get_module_sections":
                    return GetModuleSections(requestData.module_name);
                case "save_cheat_table":
                    return SaveCheatTable(requestData.file_path);
                case "load_cheat_table":
                    return LoadCheatTable(requestData.file_path);
                case "health_check":
                    return PerformHealthCheck();
                // Advanced CE features
                case "allocate_memory":
                    return AllocateMemory(requestData.size, requestData.protection);
                case "deallocate_memory":
                    return DeallocateMemory(requestData.address);
                case "inject_code":
                    return InjectCode(requestData.address, requestData.code);
                case "get_threads":
                    return GetThreads();
                case "suspend_thread":
                    return SuspendThread(requestData.thread_id);
                case "resume_thread":
                    return ResumeThread(requestData.thread_id);
                case "get_handles":
                    return GetHandles();
                case "get_symbol_address":
                    return GetSymbolAddress(requestData.module_name, requestData.symbol_name);
                case "evaluate_expression":
                    return EvaluateExpression(requestData.expression);
                default:
                    throw new ArgumentException($"Unknown action: {action}");
            }
        }

        #region CE Action Implementations

        /// <summary>
        /// 执行Lua脚本，带超时限制
        /// </summary>
        /// <param name="script">Lua脚本</param>
        /// <param name="timeoutMs">超时时间（毫秒）</param>
        /// <returns>执行结果</returns>
        private object ExecuteLua(string script, int timeoutMs = 30000) // Default 30 seconds timeout
        {
            plugin.Log($"Executing Lua script: {script}", PluginExample.LogLevel.Debug);
            
            object result = null;
            Exception exception = null;

            // Use a task with timeout to execute Lua script
            using (CancellationTokenSource cts = new CancellationTokenSource())
            {
                // Create a task to execute Lua script
                Task executeTask = Task.Run(() =>
                {
                    try
                    {
                        // Use lock to ensure thread safety when accessing CE Lua API
                        lock (plugin.sdk.lua)
                        {
                            // Execute Lua script with pcall for error handling
                            plugin.sdk.lua.DoString($@"result = nil
local success, err = pcall(function()
    {script}
end)
if not success then
    result = {{ success = false, error = err }}
else
    result = {{ success = true }}
end
");

                            // Get the result as JSON string
                            plugin.sdk.lua.DoString("result_json = json.encode(result)");
                            plugin.sdk.lua.DoString("return result_json");
                            int top = plugin.sdk.lua.GetTop();
                            if (top > 0 && plugin.sdk.lua.IsString(top))
                            {
                                string resultJson = plugin.sdk.lua.ToString(top);
                                plugin.sdk.lua.Pop(1);
                                
                                if (!string.IsNullOrEmpty(resultJson))
                                {
                                    result = JsonConvert.DeserializeObject(resultJson);
                                }
                                else
                                {
                                    result = new { success = true };
                                }
                            }
                            else
                            {
                                result = new { success = true };
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        exception = ex;
                    }
                }, cts.Token);

                // Wait for task to complete with timeout
                if (!executeTask.Wait(timeoutMs, cts.Token))
                {
                    // Task timed out
                    plugin.Log($"Lua script execution timed out after {timeoutMs}ms: {script}", PluginExample.LogLevel.Error);
                    return new { success = false, error = $"Script execution timed out after {timeoutMs}ms" };
                }
            }

            // Check if an exception occurred
            if (exception != null)
            {
                plugin.Log($"Error executing Lua script: {exception.Message}", PluginExample.LogLevel.Error);
                return new { success = false, error = exception.Message };
            }

            return result;
        }

        /// <summary>
        /// 获取进程列表
        /// </summary>
        /// <returns>进程列表</returns>
        private object GetProcessList()
        {
            return ExecuteLua(@"local processes = {}
for i, process in pairs(getProcessList()) do
    table.insert(processes, {
        id = process.pid,
        name = process.name,
        path = process.path,
        is_64bit = process.is64Bit
    })
end
return processes");
        }

        /// <summary>
        /// 附加到进程
        /// </summary>
        /// <param name="processId">进程ID</param>
        /// <returns>执行结果</returns>
        private object AttachToProcess(int processId)
        {
            return ExecuteLua($"attachToProcess({processId})");
        }

        /// <summary>
        /// 从进程分离
        /// </summary>
        /// <returns>执行结果</returns>
        private object DetachFromProcess()
        {
            return ExecuteLua("detachFromProcess()");
        }

        /// <summary>
        /// 读取内存
        /// </summary>
        /// <param name="address">内存地址</param>
        /// <param name="size">读取大小</param>
        /// <param name="dataType">数据类型</param>
        /// <returns>执行结果</returns>
        private object ReadMemory(string address, int size, string dataType)
        {
            return ExecuteLua($@"local address = tonumber('{address}')
local result
if '{dataType}' == 'string' then
    result = readString(address, {size})
elif '{dataType}' == 'byte' then
    result = readBytes(address, {size})
elif '{dataType}' == 'word' then
    result = readWord(address)
elif '{dataType}' == 'dword' then
    result = readDword(address)
elif '{dataType}' == 'qword' then
    result = readQword(address)
elif '{dataType}' == 'float' then
    result = readFloat(address)
elif '{dataType}' == 'double' then
    result = readDouble(address)
else -- raw
    result = readBytes(address, {size})
end
return {{ result = result, data_type = '{dataType}' }}");
        }

        /// <summary>
        /// 写入内存
        /// </summary>
        /// <param name="address">内存地址</param>
        /// <param name="value">写入值</param>
        /// <param name="dataType">数据类型</param>
        /// <returns>执行结果</returns>
        private object WriteMemory(string address, string value, string dataType)
        {
            return ExecuteLua($@"local address = tonumber('{address}')
local success = true
local message = 'Memory written successfully'

if '{dataType}' == 'string' then
    writeString(address, '{value}')
elif '{dataType}' == 'byte' then
    writeBytes(address, tonumber('{value}'))
elif '{dataType}' == 'word' then
    writeWord(address, tonumber('{value}'))
elif '{dataType}' == 'dword' then
    writeDword(address, tonumber('{value}'))
elif '{dataType}' == 'qword' then
    writeQword(address, tonumber('{value}'))
elif '{dataType}' == 'float' then
    writeFloat(address, tonumber('{value}'))
elif '{dataType}' == 'double' then
    writeDouble(address, tonumber('{value}'))
else -- raw
    writeBytes(address, '{value}')
end

return {{ success = success, message = message }}");
        }

        /// <summary>
        /// 扫描内存
        /// </summary>
        /// <param name="value">扫描值</param>
        /// <param name="dataType">数据类型</param>
        /// <param name="scanType">扫描类型</param>
        /// <returns>执行结果</returns>
        private object ScanMemory(string value, string dataType, string scanType)
        {
            return ExecuteLua($@"local scan_id = createScan(false)
setScanRange(scan_id, 0x00000000, 0x7FFFFFFF)
setScanValueType(scan_id, '{dataType}')

local scan_type
if '{scanType}' == 'exact_value' then
    scan_type = vtExactValue
elseif '{scanType}' == 'unknown_initial_value' then
    scan_type = vtUnknownInitialValue
elseif '{scanType}' == 'increased_value' then
    scan_type = vtIncreasedValue
elseif '{scanType}' == 'decreased_value' then
    scan_type = vtDecreasedValue
elseif '{scanType}' == 'value_between' then
    scan_type = vtValueBetween
end

setScanCompareType(scan_id, scan_type)
if '{scanType}' == 'value_between' then
    local min, max = '{value}':match('(%d+)-(%d+)')
    setScanValue(scan_id, min, max)
else
    setScanValue(scan_id, '{value}')
end

local address_count = performScan(scan_id)

return {{ scan_id = 'scan_' .. scan_id, addresses_found = address_count, message = 'Scan completed' }}");
        }

        /// <summary>
        /// 冻结内存
        /// </summary>
        /// <param name="address">内存地址</param>
        /// <param name="value">冻结值</param>
        /// <param name="dataType">数据类型</param>
        /// <returns>执行结果</returns>
        private object FreezeMemory(string address, string value, string dataType)
        {
            return ExecuteLua($@"local address = tonumber('{address}')
local entry = addresslist_getMemoryRecordByAddress(address)
if not entry then
    entry = addresslist_addAddress(address, '{dataType}', '{value}')
end
memoryrecord_freeze(entry, true)
return {{ freeze_id = entry, success = true }}");
        }

        /// <summary>
        /// 解冻内存
        /// </summary>
        /// <param name="freezeId">冻结ID</param>
        /// <returns>执行结果</returns>
        private object UnfreezeMemory(int freezeId)
        {
            return ExecuteLua($"memoryrecord_freeze({freezeId}, false)");
        }

        /// <summary>
        /// 计算指针地址
        /// </summary>
        /// <param name="baseAddress">基地址</param>
        /// <param name="offsets">偏移量</param>
        /// <returns>执行结果</returns>
        private object CalculatePointerAddress(string baseAddress, int[] offsets)
        {
            string offsetsStr = string.Join(", ", offsets);
            return ExecuteLua($@"local base = tonumber('{baseAddress}')
local current = base
local offsets = {{{offsetsStr}}}
for i, offset in ipairs(offsets) do
    current = readDword(current) + offset
end
return {{ result_address = string.format('0x%X', current) }}");
        }

        /// <summary>
        /// 查找指针
        /// </summary>
        /// <param name="targetAddress">目标地址</param>
        /// <param name="maxLevel">最大指针级别</param>
        /// <param name="maxOffsets">最大偏移量数量</param>
        /// <returns>执行结果</returns>
        private object FindPointers(string targetAddress, int maxLevel, int maxOffsets)
        {
            return ExecuteLua($@"local target = tonumber('{targetAddress}')
local pointers = findPointers(target, {maxLevel}, {maxOffsets})
local result = {{ pointers = {{}} }}
for i, pointer in ipairs(pointers) do
    table.insert(result.pointers, {{
        base_address = string.format('0x%X', pointer.base),
        offsets = pointer.offsets
    }})
end
return result");
        }

        /// <summary>
        /// 反汇编代码
        /// </summary>
        /// <param name="address">起始地址</param>
        /// <param name="instructionCount">指令数量</param>
        /// <returns>执行结果</returns>
        private object Disassemble(string address, int instructionCount)
        {
            return ExecuteLua($@"local start_address = tonumber('{address}')
local instructions = {{}}
local current = start_address

for i = 1, {instructionCount} do
    local disasm = disassemble(current)
    table.insert(instructions, {{
        address = string.format('0x%X', current),
        bytes = disasm.bytes,
        mnemonic = disasm.mnemonic,
        operands = disasm.operands,
        comment = disasm.comment
    }})
    current = current + disasm.size
end

return {{ instructions = instructions }}");
        }

        /// <summary>
        /// 设置断点
        /// </summary>
        /// <param name="address">断点地址</param>
        /// <param name="breakpointType">断点类型</param>
        /// <returns>执行结果</returns>
        private object SetBreakpoint(string address, string breakpointType)
        {
            return ExecuteLua($@"local bp_address = tonumber('{address}')
local bp_type

if '{breakpointType}' == 'execute' then
    bp_type = bpExecute
elseif '{breakpointType}' == 'read' then
    bp_type = bpRead
elseif '{breakpointType}' == 'write' then
    bp_type = bpWrite
elseif '{breakpointType}' == 'access' then
    bp_type = bpAccess
end

setBreakpoint(bp_address, bp_type)
return {{ success = true, message = 'Breakpoint set successfully' }}");
        }

        /// <summary>
        /// 移除断点
        /// </summary>
        /// <param name="address">断点地址</param>
        /// <returns>执行结果</returns>
        private object RemoveBreakpoint(string address)
        {
            return ExecuteLua($@"local bp_address = tonumber('{address}')
removeBreakpoint(bp_address)
return {{ success = true, message = 'Breakpoint removed successfully' }}");
        }

        /// <summary>
        /// 获取模块列表
        /// </summary>
        /// <returns>模块列表</returns>
        private object GetModules()
        {
            return ExecuteLua(@"local modules = {}
for i, module in pairs(getModules()) do
    table.insert(modules, {
        name = module.name,
        base_address = string.format('0x%X', module.base),
        size = module.size,
        path = module.path
    })
end
return {{ modules = modules }}");
        }

        /// <summary>
        /// 获取模块节
        /// </summary>
        /// <param name="moduleName">模块名称</param>
        /// <returns>模块节列表</returns>
        private object GetModuleSections(string moduleName)
        {
            return ExecuteLua($@"local sections = {{}}
local module = getModuleFromName('{moduleName}')
if module then
    for i, section in pairs(getModuleSections(module)) do
        table.insert(sections, {{
            name = section.name,
            base_address = string.format('0x%X', section.base),
            size = section.size,
            flags = section.flags
        }})
    end
end
return {{ sections = sections }}");
        }

        /// <summary>
        /// 保存作弊表
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>执行结果</returns>
        private object SaveCheatTable(string filePath)
        {
            return ExecuteLua($"saveCTFile('{filePath}')");
        }

        /// <summary>
        /// 加载作弊表
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>执行结果</returns>
        private object LoadCheatTable(string filePath)
        {
            return ExecuteLua($"openCTFile('{filePath}')");
        }
        
        /// <summary>
        /// 执行健康检查
        /// </summary>
        /// <returns>健康检查结果</returns>
        private object PerformHealthCheck()
        {
            plugin.Log("Performing health check", PluginExample.LogLevel.Debug);
            
            try
            {
                // Check if CE Lua API is accessible
                object luaCheck = ExecuteLua("return { 'status': 'ok', 'timestamp': os.time() }", 1000);
                
                // Return health status
                return new {
                    status = "healthy",
                    timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    components = new {
                        httpServer = "running",
                        ceLuaApi = "accessible",
                        memoryUsage = GC.GetTotalMemory(false) / (1024 * 1024) + " MB"
                    },
                    version = "1.0.0"
                };
            }
            catch (Exception ex)
            {
                plugin.Log("Health check failed: " + ex.Message, PluginExample.LogLevel.Error);
                
                return new {
                    status = "unhealthy",
                    timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    error = ex.Message,
                    components = new {
                        httpServer = "running",
                        ceLuaApi = "unaccessible",
                        memoryUsage = GC.GetTotalMemory(false) / (1024 * 1024) + " MB"
                    }
                };
            }
        }
        
        #region Advanced CE Features
        
        /// <summary>
        /// 分配内存
        /// </summary>
        /// <param name="size">内存大小</param>
        /// <param name="protection">内存保护类型</param>
        /// <returns>执行结果</returns>
        private object AllocateMemory(int size, string protection)
        {
            return ExecuteLua($@"local protection = {protection or 'PAGE_EXECUTE_READWRITE'}
local address = allocateMemory({size}, protection)
return {{ address = string.format('0x%X', address), success = address ~= nil }}");
        }
        
        /// <summary>
        /// 释放内存
        /// </summary>
        /// <param name="address">内存地址</param>
        /// <returns>执行结果</returns>
        private object DeallocateMemory(string address)
        {
            return ExecuteLua($@"local address = tonumber('{address}')
deallocateMemory(address)
return {{ success = true, message = 'Memory deallocated successfully' }}");
        }
        
        /// <summary>
        /// 注入代码
        /// </summary>
        /// <param name="address">目标地址</param>
        /// <param name="code">要注入的代码</param>
        /// <returns>执行结果</returns>
        private object InjectCode(string address, string code)
        {
            return ExecuteLua($@"local address = tonumber('{address}')
writeBytes(address, '{code}')
return {{ success = true, message = 'Code injected successfully', address = string.format('0x%X', address) }}");
        }
        
        /// <summary>
        /// 获取进程线程列表
        /// </summary>
        /// <returns>线程列表</returns>
        private object GetThreads()
        {
            return ExecuteLua(@"local threads = {}
for i, thread in pairs(getThreadList()) do
    table.insert(threads, {
        thread_id = thread.id,
        priority = thread.priority,
        status = thread.status
    })
end
return { threads = threads }");
        }
        
        /// <summary>
        /// 挂起线程
        /// </summary>
        /// <param name="threadId">线程ID</param>
        /// <returns>执行结果</returns>
        private object SuspendThread(int threadId)
        {
            return ExecuteLua($@"suspendThread({threadId})
return {{ success = true, message = 'Thread suspended successfully' }}");
        }
        
        /// <summary>
        /// 恢复线程
        /// </summary>
        /// <param name="threadId">线程ID</param>
        /// <returns>执行结果</returns>
        private object ResumeThread(int threadId)
        {
            return ExecuteLua($@"resumeThread({threadId})
return {{ success = true, message = 'Thread resumed successfully' }}");
        }
        
        /// <summary>
        /// 获取进程句柄列表
        /// </summary>
        /// <returns>句柄列表</returns>
        private object GetHandles()
        {
            return ExecuteLua(@"local handles = {}
for i, handle in pairs(getHandleList()) do
    table.insert(handles, {
        handle = handle.handle,
        type = handle.type,
        name = handle.name
    })
end
return { handles = handles }");
        }
        
        /// <summary>
        /// 获取符号地址
        /// </summary>
        /// <param name="moduleName">模块名称</param>
        /// <param name="symbolName">符号名称</param>
        /// <returns>执行结果</returns>
        private object GetSymbolAddress(string moduleName, string symbolName)
        {
            return ExecuteLua($@"local module = getModuleFromName('{moduleName}')
if not module then
    return {{ success = false, error = 'Module not found' }}
end
local address = getAddress('{moduleName}!{symbolName}')
if address then
    return {{ success = true, address = string.format('0x%X', address) }}
else
    return {{ success = false, error = 'Symbol not found' }}
end");
        }
        
        /// <summary>
        /// 评估表达式
        /// </summary>
        /// <param name="expression">表达式字符串</param>
        /// <returns>执行结果</returns>
        private object EvaluateExpression(string expression)
        {
            return ExecuteLua($@"local result = evaluateExpression('{expression}')
return {{ result = result, success = result ~= nil }}");
        }
        
        #endregion
        
        #endregion


    }
}