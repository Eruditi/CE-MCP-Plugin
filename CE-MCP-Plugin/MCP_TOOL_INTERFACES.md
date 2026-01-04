# CE MCP Plugin - 工具接口规范

## 1. 进程管理模块

### 1.1 ce_get_process_list
**描述**：获取运行中的进程列表

**参数**：
```json
{
  "type": "object",
  "properties": {}
}
```

**返回值**：
```json
{
  "processes": [
    {
      "id": 1234,
      "name": "example.exe",
      "path": "C:\\Program Files\\Example\\example.exe",
      "is_64bit": true
    }
  ]
}
```

### 1.2 ce_attach_to_process
**描述**：附加到指定进程

**参数**：
```json
{
  "type": "object",
  "properties": {
    "process_id": {
      "type": "integer",
      "description": "进程ID"
    }
  },
  "required": ["process_id"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "成功附加到进程"
}
```

### 1.3 ce_detach_from_process
**描述**：从当前进程分离

**参数**：
```json
{
  "type": "object",
  "properties": {}
}
```

**返回值**：
```json
{
  "success": true,
  "message": "成功从进程分离"
}
```

## 2. 内存操作模块

### 2.1 ce_read_memory
**描述**：读取指定进程的内存

**参数**：
```json
{
  "type": "object",
  "properties": {
    "process_id": {
      "type": "integer",
      "description": "进程ID（可选，默认当前附加进程）"
    },
    "address": {
      "type": "string",
      "description": "内存地址（十六进制格式）"
    },
    "size": {
      "type": "integer",
      "description": "读取的字节数"
    },
    "data_type": {
      "type": "string",
      "description": "数据类型（可选，默认raw）",
      "enum": ["raw", "byte", "word", "dword", "qword", "float", "double", "string"]
    }
  },
  "required": ["address", "size"]
}
```

**返回值**：
```json
{
  "result": "0x12345678",
  "data_type": "dword"
}
```

### 2.2 ce_write_memory
**描述**：写入指定进程的内存

**参数**：
```json
{
  "type": "object",
  "properties": {
    "process_id": {
      "type": "integer",
      "description": "进程ID（可选，默认当前附加进程）"
    },
    "address": {
      "type": "string",
      "description": "内存地址（十六进制格式）"
    },
    "value": {
      "type": "string",
      "description": "要写入的值"
    },
    "data_type": {
      "type": "string",
      "description": "数据类型（可选，默认raw）",
      "enum": ["raw", "byte", "word", "dword", "qword", "float", "double", "string"]
    }
  },
  "required": ["address", "value"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "内存写入成功"
}
```

### 2.3 ce_scan_memory
**描述**：扫描进程内存

**参数**：
```json
{
  "type": "object",
  "properties": {
    "process_id": {
      "type": "integer",
      "description": "进程ID（可选，默认当前附加进程）"
    },
    "value": {
      "type": "string",
      "description": "要扫描的值"
    },
    "data_type": {
      "type": "string",
      "description": "数据类型",
      "enum": ["byte", "word", "dword", "qword", "float", "double", "string", "array"]
    },
    "scan_type": {
      "type": "string",
      "description": "扫描类型",
      "enum": ["exact_value", "unknown_initial_value", "increased_value", "decreased_value", "value_between"]
    },
    "memory_regions": {
      "type": "array",
      "description": "要扫描的内存区域（可选）",
      "items": {
        "type": "object",
        "properties": {
          "start": { "type": "string" },
          "end": { "type": "string" }
        }
      }
    }
  },
  "required": ["value", "data_type", "scan_type"]
}
```

**返回值**：
```json
{
  "scan_id": "scan_123",
  "addresses_found": 42,
  "message": "扫描完成"
}
```

### 2.4 ce_freeze_memory
**描述**：冻结指定内存地址

**参数**：
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "内存地址（十六进制格式）"
    },
    "value": {
      "type": "string",
      "description": "冻结的值"
    },
    "data_type": {
      "type": "string",
      "description": "数据类型",
      "enum": ["byte", "word", "dword", "qword", "float", "double"]
    }
  },
  "required": ["address", "value", "data_type"]
}
```

**返回值**：
```json
{
  "freeze_id": 123,
  "success": true
}
```

### 2.5 ce_unfreeze_memory
**描述**：解冻指定内存地址

**参数**：
```json
{
  "type": "object",
  "properties": {
    "freeze_id": {
      "type": "integer",
      "description": "冻结ID"
    }
  },
  "required": ["freeze_id"]
}
```

**返回值**：
```json
{
  "success": true
}
```

## 3. 指针操作模块

### 3.1 ce_calculate_pointer_address
**描述**：计算指针地址

**参数**：
```json
{
  "type": "object",
  "properties": {
    "base_address": {
      "type": "string",
      "description": "基地址（十六进制格式）"
    },
    "offsets": {
      "type": "array",
      "description": "偏移量列表",
      "items": {
        "type": "integer"
      }
    }
  },
  "required": ["base_address", "offsets"]
}
```

**返回值**：
```json
{
  "result_address": "0x12345678"
}
```

### 3.2 ce_find_pointers
**描述**：查找指向特定地址的指针

**参数**：
```json
{
  "type": "object",
  "properties": {
    "target_address": {
      "type": "string",
      "description": "目标地址（十六进制格式）"
    },
    "max_level": {
      "type": "integer",
      "description": "最大指针级别",
      "default": 5
    },
    "max_offsets": {
      "type": "integer",
      "description": "每个指针的最大偏移量数量",
      "default": 1000
    }
  },
  "required": ["target_address"]
}
```

**返回值**：
```json
{
  "pointers": [
    {
      "base_address": "0x400000",
      "offsets": [0x10, 0x20, 0x30]
    }
  ]
}
```

## 4. 反汇编和调试模块

### 4.1 ce_disassemble
**描述**：反汇编指定地址的代码

**参数**：
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "起始地址（十六进制格式）"
    },
    "instruction_count": {
      "type": "integer",
      "description": "要反汇编的指令数量",
      "default": 10
    }
  },
  "required": ["address"]
}
```

**返回值**：
```json
{
  "instructions": [
    {
      "address": "0x12345678",
      "bytes": "8B 05 00 00 00 00",
      "mnemonic": "mov",
      "operands": "eax, [0x1234567C]",
      "comment": "Load value from memory into EAX"
    },
    {
      "address": "0x1234567E",
      "bytes": "83 C0 01",
      "mnemonic": "add",
      "operands": "eax, 0x1",
      "comment": "Increment EAX by 1"
    }
  ]
}
```

### 4.2 ce_set_breakpoint
**描述**：设置断点

**参数**：
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "地址（十六进制格式）"
    },
    "breakpoint_type": {
      "type": "string",
      "description": "断点类型",
      "enum": ["execute", "read", "write", "access"]
    }
  },
  "required": ["address", "breakpoint_type"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "Breakpoint set successfully"
}
```

### 4.3 ce_remove_breakpoint
**描述**：移除断点

**参数**：
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "地址（十六进制格式）"
    }
  },
  "required": ["address"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "Breakpoint removed successfully"
}
```

## 5. Lua脚本支持模块

### 5.1 ce_execute_lua
**描述**：执行Lua脚本

**参数**：
```json
{
  "type": "object",
  "properties": {
    "script": {
      "type": "string",
      "description": "Lua脚本"
    }
  },
  "required": ["script"]
}
```

**返回值**：
```json
{
  "result": "Script executed successfully",
  "success": true
}
```

## 6. 模块和节管理模块

### 6.1 ce_get_modules
**描述**：获取当前进程中的模块列表

**参数**：
```json
{
  "type": "object",
  "properties": {
    "process_id": {
      "type": "integer",
      "description": "进程ID（可选，默认当前附加进程）"
    }
  }
}
```

**返回值**：
```json
{
  "modules": [
    {
      "name": "kernel32.dll",
      "base_address": "0x773D0000",
      "size": 1572864,
      "path": "C:\Windows\System32\kernel32.dll"
    }
  ]
}
```

### 6.2 ce_get_module_sections
**描述**：获取特定模块的节

**参数**：
```json
{
  "type": "object",
  "properties": {
    "module_name": {
      "type": "string",
      "description": "模块名称（例如：kernel32.dll）"
    }
  },
  "required": ["module_name"]
}
```

**返回值**：
```json
{
  "sections": [
    {
      "name": ".text",
      "base_address": "0x401000",
      "size": 102400,
      "flags": "CODE EXECUTE READ"
    }
  ]
}
```

## 7. 作弊表管理模块

### 7.1 ce_save_cheat_table
**描述**：将当前作弊表保存到文件

**参数**：
```json
{
  "type": "object",
  "properties": {
    "file_path": {
      "type": "string",
      "description": "作弊表文件路径"
    }
  },
  "required": ["file_path"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "Cheat table saved successfully"
}
```

### 7.2 ce_load_cheat_table
**描述**：从文件加载作弊表

**参数**：
```json
{
  "type": "object",
  "properties": {
    "file_path": {
      "type": "string",
      "description": "作弊表文件路径"
    }
  },
  "required": ["file_path"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "Cheat table loaded successfully"
}
```

## 8. 高级内存管理模块

### 8.1 ce_allocate_memory
**描述**：在当前进程中分配内存

**参数**：
```json
{
  "type": "object",
  "properties": {
    "size": {
      "type": "integer",
      "description": "要分配的内存大小（字节）"
    },
    "protection": {
      "type": "string",
      "description": "内存保护类型",
      "enum": ["PAGE_NOACCESS", "PAGE_READONLY", "PAGE_READWRITE", "PAGE_EXECUTE", "PAGE_EXECUTE_READ", "PAGE_EXECUTE_READWRITE"],
      "default": "PAGE_EXECUTE_READWRITE"
    }
  },
  "required": ["size"]
}
```

**返回值**：
```json
{
  "address": "0x12345678",
  "success": true
}
```

### 8.2 ce_deallocate_memory
**描述**：释放指定地址的内存

**参数**：
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "要释放的内存地址（十六进制格式）"
    }
  },
  "required": ["address"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "Memory deallocated successfully"
}
```

### 8.3 ce_inject_code
**描述**：向指定内存地址注入代码

**参数**：
```json
{
  "type": "object",
  "properties": {
    "address": {
      "type": "string",
      "description": "目标地址（十六进制格式）"
    },
    "code": {
      "type": "string",
      "description": "要注入的十六进制代码"
    }
  },
  "required": ["address", "code"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "Code injected successfully",
  "address": "0x12345678"
}
```

## 9. 线程管理模块

### 9.1 ce_get_threads
**描述**：获取当前进程的线程列表

**参数**：
```json
{
  "type": "object",
  "properties": {}
}
```

**返回值**：
```json
{
  "threads": [
    {
      "thread_id": 1234,
      "priority": 10,
      "status": "running"
    }
  ]
}
```

### 9.2 ce_suspend_thread
**描述**：挂起指定线程

**参数**：
```json
{
  "type": "object",
  "properties": {
    "thread_id": {
      "type": "integer",
      "description": "要挂起的线程ID"
    }
  },
  "required": ["thread_id"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "Thread suspended successfully"
}
```

### 9.3 ce_resume_thread
**描述**：恢复指定线程

**参数**：
```json
{
  "type": "object",
  "properties": {
    "thread_id": {
      "type": "integer",
      "description": "要恢复的线程ID"
    }
  },
  "required": ["thread_id"]
}
```

**返回值**：
```json
{
  "success": true,
  "message": "Thread resumed successfully"
}
```

## 10. 句柄管理模块

### 10.1 ce_get_handles
**描述**：获取当前进程的句柄列表

**参数**：
```json
{
  "type": "object",
  "properties": {}
}
```

**返回值**：
```json
{
  "handles": [
    {
      "handle": 1234,
      "type": "File",
      "name": "C:\\example.txt"
    }
  ]
}
```

## 11. 符号和表达式模块

### 11.1 ce_get_symbol_address
**描述**：获取模块中符号的地址

**参数**：
```json
{
  "type": "object",
  "properties": {
    "module_name": {
      "type": "string",
      "description": "模块名称（例如：kernel32.dll）"
    },
    "symbol_name": {
      "type": "string",
      "description": "符号名称"
    }
  },
  "required": ["module_name", "symbol_name"]
}
```

**返回值**：
```json
{
  "success": true,
  "address": "0x773D1234"
}
```

### 11.2 ce_evaluate_expression
**描述**：评估Cheat Engine上下文的表达式

**参数**：
```json
{
  "type": "object",
  "properties": {
    "expression": {
      "type": "string",
      "description": "要评估的表达式"
    }
  },
  "required": ["expression"]
}
```

**返回值**：
```json
{
  "result": "0x12345678",
  "success": true
}
```

## 12. 健康检查模块

### 12.1 ce_health_check
**描述**：执行插件和CE集成的健康检查

**参数**：
```json
{
  "type": "object",
  "properties": {}
}
```

**返回值**：
```json
{
  "status": "healthy",
  "timestamp": "2023-06-15 14:30:00.123",
  "components": {
    "httpServer": "running",
    "ceLuaApi": "accessible",
    "memoryUsage": "10.5 MB"
  },
  "version": "1.0.0"
}
```