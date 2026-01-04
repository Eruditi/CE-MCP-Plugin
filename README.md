# CE MCP Plugin

## 功能描述

CE MCP Plugin是一个Cheat Engine插件，它实现了Model Context Protocol (MCP)，允许AI模型与Cheat Engine进行交互。通过这个插件，AI可以使用Cheat Engine的各种功能，如内存读写、进程管理等。

## 主要功能

1. **MCP服务器**：启动一个MCP服务器，允许AI模型连接并使用Cheat Engine的功能
2. **进程管理**：获取运行中的进程列表、附加/分离进程
3. **内存操作**：读取和写入进程内存、扫描内存、冻结/解冻内存
4. **指针操作**：计算指针地址、查找指针
5. **反汇编和调试**：反汇编代码、设置/移除断点
6. **模块和节管理**：获取模块列表、获取模块节
7. **作弊表管理**：保存/加载作弊表
8. **Lua脚本支持**：执行Lua脚本
9. **高级内存管理**：分配/释放内存、注入代码
10. **线程管理**：获取线程列表、挂起/恢复线程
11. **句柄管理**：获取进程句柄列表
12. **符号和表达式**：获取符号地址、评估表达式
13. **健康检查**：插件和CE集成的健康状态检查
14. **可扩展工具集**：支持CE的所有核心功能

## 安全性和稳定性增强

1. **请求速率限制**：使用令牌桶算法限制每个客户端每分钟60个请求
2. **输入验证**：严格的请求验证，包括内容类型、大小限制和JSON语法验证
3. **安全线程管理**：使用CancellationToken替代Thread.Abort进行安全线程终止
4. **超时机制**：所有外部操作都有超时限制，防止无限等待
5. **请求重试机制**：带指数退避的请求重试逻辑
6. **健康监控**：内置健康检查端点，可监控插件状态
7. **错误处理**：完善的错误处理和日志记录机制
8. **线程安全**：所有CE API调用都进行了线程安全保护
9. **资源管理**：严格的资源清理和IDisposable实现
10. **配置管理**：完整的配置系统，支持自定义端口、日志级别等
11. **可配置日志**：支持不同日志级别，日志文件大小自动管理
12. **CORS支持**：允许跨域请求（仅用于开发环境）

## 安装方法

1. 编译插件：
   - 使用Visual Studio打开`CEPluginLibrary.sln`
   - 选择Release配置，编译项目
   - 在`bin/Release`目录中找到生成的`CEPluginExample.dll`文件

2. 安装插件：
   - 将`CEPluginExample.dll`复制到Cheat Engine的`plugins`目录
   - 启动Cheat Engine，在插件列表中启用"CE MCP Plugin"

## 使用方法

1. **启动MCP服务器**：
   - 在Cheat Engine菜单中选择`CE MCP Plugin` > `Start MCP Server`
   - 或者在Lua脚本中执行`startMCPServer()`

2. **停止MCP服务器**：
   - 在Cheat Engine菜单中选择`CE MCP Plugin` > `Stop MCP Server`
   - 或者在Lua脚本中执行`stopMCPServer()`

3. **AI模型连接**：
   - MCP服务器默认运行在`http://localhost:18888`
   - AI模型可以通过这个地址连接到MCP服务器

## MCP工具接口

插件实现了完整的Cheat Engine功能接口，详细的接口定义请参考 [MCP_TOOL_INTERFACES.md](MCP_TOOL_INTERFACES.md) 文件。

主要接口类别包括：

1. **进程管理模块**
   - `ce_get_process_list`: 获取运行中的进程列表
   - `ce_attach_to_process`: 附加到指定进程
   - `ce_detach_from_process`: 从当前进程分离

2. **内存操作模块**
   - `ce_read_memory`: 读取指定进程的内存
   - `ce_write_memory`: 写入指定进程的内存
   - `ce_scan_memory`: 扫描进程内存
   - `ce_freeze_memory`: 冻结指定内存地址
   - `ce_unfreeze_memory`: 解冻指定内存地址

3. **指针操作模块**
   - `ce_calculate_pointer_address`: 计算指针地址
   - `ce_find_pointers`: 查找指向特定地址的指针

4. **反汇编和调试模块**
   - `ce_disassemble`: 反汇编指定地址的代码
   - `ce_set_breakpoint`: 设置断点
   - `ce_remove_breakpoint`: 移除断点

5. **Lua脚本支持模块**
   - `ce_execute_lua`: 执行Lua脚本

6. **模块和节管理模块**
   - `ce_get_modules`: 获取当前进程中的模块列表
   - `ce_get_module_sections`: 获取特定模块的节

7. **作弊表管理模块**
   - `ce_save_cheat_table`: 将当前作弊表保存到文件
   - `ce_load_cheat_table`: 从文件加载作弊表

8. **高级内存管理模块**
   - `ce_allocate_memory`: 在当前进程中分配内存
   - `ce_deallocate_memory`: 释放指定地址的内存
   - `ce_inject_code`: 向指定内存地址注入代码

9. **线程管理模块**
   - `ce_get_threads`: 获取当前进程的线程列表
   - `ce_suspend_thread`: 挂起指定线程
   - `ce_resume_thread`: 恢复指定线程

10. **句柄管理模块**
    - `ce_get_handles`: 获取当前进程的句柄列表

11. **符号和表达式模块**
    - `ce_get_symbol_address`: 获取模块中符号的地址
    - `ce_evaluate_expression`: 评估Cheat Engine上下文的表达式

12. **健康检查模块**
    - `ce_health_check`: 执行插件和CE集成的健康检查

## 技术实现

- **插件框架**：基于Cheat Engine的C#插件模板
- **MCP服务器**：使用Python的fastmcp库
- **通信方式**：HTTP/JSON-RPC

## 开发说明

- 插件使用.NET Framework 4.7.2开发
- 插件会自动检查Python环境和fastmcp库，若未安装会自动安装
- 插件在启动时会创建一个唯一的临时Python脚本，并在单独的进程中运行
- 插件实现了完善的错误处理和日志记录机制
- 支持CE SDK版本6

## 注意事项

- 确保Python已安装并添加到系统PATH中
- MCP服务器默认运行在端口18888，请确保该端口未被占用
- 插件需要Cheat Engine 7.1或更高版本
- 使用该插件时，请遵守相关法律法规和游戏规则
- 插件在启动时会检查并自动安装fastmcp库
- 插件会生成日志文件，位于`%APPDATA%\Cheat Engine\Plugins\CEMCPPlugin\plugin.log`

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request来改进这个插件！

## 联系方式

如有问题或建议，请通过以下方式联系：
- 提交GitHub Issue
- 发送邮件至：[evildoerhacker@gmail.com]