# CE-MCP-Plugin

Cheat Engine MCP (Memory Cheat Plugin) - AI Integration Plugin for Cheat Engine

## 项目简介

CE-MCP-Plugin是一个为Cheat Engine开发的AI集成插件，允许Cheat Engine与外部AI工具建立稳定连接，接收并执行AI发送的指令。该插件为Cheat Engine提供了AI驱动的内存修改和游戏作弊功能。

## 功能特性

### AI连接功能
- 与AI服务器建立TCP连接
- 支持接收和解析AI指令
- 支持通过Lua脚本向AI发送命令
- 异步通信设计，不阻塞Cheat Engine主界面

### 指令支持

本插件支持**75个命令**，涵盖以下功能类别：

#### 基础功能
- **SHOW_MESSAGE**: 显示消息框
- **PAUSE_PROCESS**: 暂停目标进程
- **UNPAUSE_PROCESS**: 恢复目标进程

#### 内存操作
- **READ_MEMORY**: 读取内存，格式：`READ_MEMORY:address,type`
- **WRITE_MEMORY**: 写入内存，格式：`WRITE_MEMORY:address,value,type`
- **FREEZE_MEMORY**: 冻结内存，格式：`FREEZE_MEMORY:address,size`
- **UNFREEZE_MEMORY**: 解冻内存，格式：`UNFREEZE_MEMORY:freeze_id`
- **FIX_MEMORY**: 修复内存，格式：`FIX_MEMORY`

#### 汇编与反汇编
- **AUTO_ASSEMBLE**: 执行自动汇编脚本
- **ASSEMBLE**: 汇编指令，格式：`ASSEMBLE:address,instruction`
- **DISASSEMBLE**: 反汇编指令，格式：`DISASSEMBLE:address`
- **DISASSEMBLE_EX**: 增强反汇编指令，提供更详细的指令信息，格式：`DISASSEMBLE_EX:address`

#### 寄存器操作
- **CHANGE_REGISTER**: 修改寄存器，格式：`CHANGE_REGISTER:address,register_name,value`

#### DLL注入
- **INJECT_DLL**: 注入DLL，格式：`INJECT_DLL:dll_path,optional_function_name`

#### 进程管理
- **PROCESS_LIST**: 获取进程列表，格式：`PROCESS_LIST`
- **GET_PROCESS_ID**: 根据进程名获取进程ID，格式：`GET_PROCESS_ID:process_name`
- **OPEN_PROCESS**: 打开进程，格式：`OPEN_PROCESS:process_id`

#### 变速齿轮
- **SPEEDHACK**: 设置游戏速度，格式：`SPEEDHACK:speed_value`

#### 高级功能
- **GET_ADDRESS_FROM_POINTER**: 通过基址和偏移获取最终地址
- **ADDRESS_TO_NAME**: 将地址转换为符号名称
- **NAME_TO_ADDRESS**: 将符号名称转换为地址
- **PREVIOUS_OPCODE**: 获取指定地址的前一条指令
- **NEXT_OPCODE**: 获取指定地址的下一条指令
- **SET_BREAKPOINT**: 设置断点
- **REMOVE_BREAKPOINT**: 移除断点
- **CONTINUE_FROM_BREAKPOINT**: 从断点继续执行

#### 内存表管理（18个命令）
- **CREATE_TABLE_ENTRY**: 创建新的内存表条目
- **GET_TABLE_ENTRY**: 获取内存表条目
- **SET_ENTRY_DESCRIPTION**: 设置条目描述
- **GET_ENTRY_DESCRIPTION**: 获取条目描述
- **SET_ENTRY_ADDRESS**: 设置条目地址
- **GET_ENTRY_ADDRESS**: 获取条目地址
- **SET_ENTRY_TYPE**: 设置条目类型
- **GET_ENTRY_TYPE**: 获取条目类型
- **SET_ENTRY_VALUE**: 设置条目值
- **GET_ENTRY_VALUE**: 获取条目值
- **SET_ENTRY_SCRIPT**: 设置条目脚本
- **GET_ENTRY_SCRIPT**: 获取条目脚本
- **SET_ENTRY_COLOR**: 设置条目颜色
- **FREEZE_ENTRY**: 冻结条目
- **UNFREEZE_ENTRY**: 解冻条目
- **IS_ENTRY_FROZEN**: 检查条目是否冻结
- **MEMREC_APPENDTOENTRY**: 追加到条目
- **DELETE_ENTRY**: 删除条目

#### 窗口管理（11个命令）
- **GET_MAIN_WINDOW_HANDLE**: 获取主窗口句柄
- **HIDE_ALL_CE_WINDOWS**: 隐藏所有CE窗口
- **UNHIDE_MAIN_CE_WINDOW**: 显示主CE窗口
- **MESSAGE_DIALOG**: 显示消息对话框
- **CLOSE_CE**: 关闭Cheat Engine
- **FORM_CENTER_SCREEN**: 表单居中
- **FORM_HIDE**: 隐藏表单
- **FORM_SHOW**: 显示表单
- **IMAGE_LOAD_IMAGE_FROM_FILE**: 从文件加载图像
- **IMAGE_TRANSPARENT**: 设置图像透明度
- **IMAGE_STRETCH**: 拉伸图像

#### UI控件管理（13个命令）
- **CREATE_PANEL**: 创建面板
- **CREATE_BUTTON**: 创建按钮
- **CREATE_LABEL**: 创建标签
- **CREATE_EDIT**: 创建编辑框
- **CREATE_COMBO_BOX**: 创建下拉框
- **CREATE_CHECK_BOX**: 创建复选框
- **CREATE_TIMER**: 创建定时器
- **TIMER_SET_INTERVAL**: 设置定时器间隔
- **CREATE_MEMO**: 创建备忘录
- **CREATE_GROUP_BOX**: 创建分组框
- **CONTROL_SET_CAPTION**: 设置控件标题
- **CONTROL_GET_CAPTION**: 获取控件标题
- **CONTROL_SET_POSITION**: 设置控件位置
- **CONTROL_GET_POSITION**: 获取控件位置
- **CONTROL_SET_SIZE**: 设置控件大小
- **CONTROL_GET_SIZE**: 获取控件大小
- **DESTROY_OBJECT**: 销毁对象

#### 其他功能
- **LOAD_MODULE**: 加载模块
- **GENERATE_API_HOOK_SCRIPT**: 生成API Hook脚本
- **DEBUG_PROCESS**: 调试进程
- **AA_ADD_COMMAND**: 添加AutoAssembler命令
- **AA_DEL_COMMAND**: 删除AutoAssembler命令

### Cheat Engine集成
- 注册主菜单插件，快捷键Ctrl+A
- 提供Lua API，支持CE脚本调用
- 动态加载和卸载支持
- 完整的CE SDK集成

## 技术栈

- 语言: C
- 开发环境: Visual Studio 2019+
- 依赖: Windows SDK, Winsock2
- Cheat Engine SDK版本: 6

## 安装方法

1. 编译插件：
   - 使用Visual Studio打开`CE-MCP-Plugin.sln`
   - 选择Release配置和Win32平台
   - 编译生成`CE-MCP-Plugin.dll`

2. 安装插件：
   - 将编译好的`CE-MCP-Plugin.dll`复制到Cheat Engine的`plugins`目录
   - 启动Cheat Engine
   - 在Cheat Engine主菜单中找到"CE-MCP-Plugin"选项

## 使用说明

### 1. 配置AI服务器

插件默认连接到`127.0.0.1:8888`地址。要修改AI服务器地址，请修改源代码中的以下变量：

```c
char aiServerIP[16] = "127.0.0.1"; // AI服务器IP
int aiServerPort = 8888; // AI服务器端口
```

### 2. 启动插件

1. 启动Cheat Engine
2. 插件会自动加载并尝试连接到AI服务器
3. 成功连接后会显示"Connected to AI server"消息
4. 在Cheat Engine主菜单中可以找到"CE-MCP-Plugin"选项

### 3. AI命令格式

AI服务器可以向插件发送以下格式的命令：

```
COMMAND:parameters
```

例如：
```
SHOW_MESSAGE:Hello from AI
SPEEDHACK:2.0
AUTO_ASSEMBLE:[ENABLE]\nalloc(newmem,2048)\nnewmem:\n  mov eax,100\n  ret\n[DISABLE]\n  dealloc(newmem)
```

### 4. 使用Lua API

插件提供了`aiSendCommand` Lua函数，可以在CE脚本中调用：

```lua
-- 向AI发送命令
local result = aiSendCommand("GET_HEALTH:player1")
print(result)
```

## 开发说明

### 项目结构

```
CE-MCP-Plugin/
├── CE-MCP-Plugin.c          # 主源代码文件（1611行，75个命令）
├── CE-MCP-Plugin.def        # DLL导出函数定义
├── CE-MCP-Plugin.sln        # Visual Studio解决方案
├── CE-MCP-Plugin.vcxproj    # Visual Studio项目文件
├── .github/
│   └── workflows/
│       └── msbuild.yml      # GitHub Actions CI/CD工作流
├── bla.cpp                  # 示例辅助文件
├── bla.h                    # 示例头文件
├── cepluginsdk.h            # Cheat Engine SDK头文件
├── lua.h                    # Lua 5.3头文件
├── lualib.h                 # Lua标准库头文件
├── lauxlib.h                # Lua辅助库头文件
├── luaconf.h                # Lua配置头文件
├── example-c.vcproj         # 示例项目文件
├── example-c.vcxproj.filters # 示例项目过滤器
└── README.md                # 项目文档
```

### 编译选项

- 支持Win32和x64平台
- 支持Debug和Release配置
- 依赖Cheat Engine SDK头文件

### 扩展开发

要添加新的AI指令支持，请修改`ExecuteAICommand`函数：

```c
void ExecuteAICommand(AICommand* cmd) {
    if (strcmp(cmd->command, "NEW_COMMAND") == 0) {
        // 实现新指令逻辑
    }
    // 其他指令...
}
```

## 注意事项

1. 确保AI服务器正在指定端口运行
2. 插件仅支持Windows平台
3. 需要Cheat Engine 7.0或更高版本
4. 建议在测试环境中使用，避免在在线游戏中使用
5. 使用时请遵守相关法律法规

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 更新日志

### v1.0 (2026-01-04)
- 初始版本发布
- 实现AI连接功能
- 支持多种CE操作指令
- 提供Lua API

## 联系方式

如有问题或建议，请通过以下方式联系：

- 提交GitHub Issue
- 发送邮件至：[evildoerhacker@gmail.com]
---

**免责声明**：本插件仅用于学习和研究目的，请勿用于非法用途。使用本插件造成的任何后果，由使用者自行承担。