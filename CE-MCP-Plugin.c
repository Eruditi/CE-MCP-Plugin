// CE-MCP-Plugin.c : Defines the entry point for the DLL application.
// Cheat Engine MCP (Memory Cheat Plugin) for AI integration

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cepluginsdk.h"
#include "bla.h"

// Link with Winsock library
#pragma comment(lib, "ws2_32.lib")

// Plugin global variables
int selfid;
ExportedFunctions Exported;

// AI connection variables
SOCKET aiSocket = INVALID_SOCKET;
HANDLE aiThread = NULL;
BOOL isRunning = FALSE;
CRITICAL_SECTION aiCriticalSection; // Critical section for thread synchronization
char aiServerIP[16] = "127.0.0.1"; // Default AI server IP
int aiServerPort = 8888; // Default AI server port

// AI command structure
typedef struct {
    char command[64];
    char parameters[512];
} AICommand;

// Initialize Winsock
BOOL InitWinsock() {
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        Exported.ShowMessage("WSAStartup failed");
        return FALSE;
    }
    return TRUE;
}

// Cleanup Winsock
void CleanupWinsock() {
    WSACleanup();
}

// Connect to AI server with timeout
BOOL ConnectToAIServer() {
    struct addrinfo *result = NULL, *ptr = NULL, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    char portStr[6];
    sprintf_s(portStr, sizeof(portStr), "%d", aiServerPort);
    
    int iResult = getaddrinfo(aiServerIP, portStr, &hints, &result);
    if (iResult != 0) {
        // Silent failure - don't block UI
        return FALSE;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        // Create a SOCKET for connecting to server
        aiSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (aiSocket == INVALID_SOCKET) {
            // Silent failure - don't block UI
            // Don't freeaddrinfo here, we'll do it after the loop
            continue;
        }

        // Set socket to non-blocking mode for timeout
        u_long mode = 1;
        if (ioctlsocket(aiSocket, FIONBIO, &mode) == SOCKET_ERROR) {
            // Silent failure - don't block UI
            closesocket(aiSocket);
            aiSocket = INVALID_SOCKET;
            continue;
        }
        
        // Connect to server (non-blocking)
        iResult = connect(aiSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                closesocket(aiSocket);
                aiSocket = INVALID_SOCKET;
                continue;
            }
            
            // Wait for connection with timeout (3 seconds)
            fd_set writefds, exceptfds;
            FD_ZERO(&writefds);
            FD_ZERO(&exceptfds);
            FD_SET(aiSocket, &writefds);
            FD_SET(aiSocket, &exceptfds);
            
            struct timeval timeout;
            timeout.tv_sec = 3;
            timeout.tv_usec = 0;
            
            iResult = select(0, NULL, &writefds, &exceptfds, &timeout);
            if (iResult == 0) {
                // Connection timeout - silent failure, don't block UI
                closesocket(aiSocket);
                aiSocket = INVALID_SOCKET;
                continue;
            } else if (iResult == SOCKET_ERROR) {
                // select error - silent failure, don't block UI
                closesocket(aiSocket);
                aiSocket = INVALID_SOCKET;
                continue;
            }
            
            // Check if connection succeeded
            if (FD_ISSET(aiSocket, &exceptfds)) {
                closesocket(aiSocket);
                aiSocket = INVALID_SOCKET;
                continue;
            }
        }
        
        // Set socket back to blocking mode
        mode = 0;
        if (ioctlsocket(aiSocket, FIONBIO, &mode) == SOCKET_ERROR) {
            // Silent failure - don't block UI
            closesocket(aiSocket);
            aiSocket = INVALID_SOCKET;
            freeaddrinfo(result);
            return FALSE;
        }
        
        break;
    }

    freeaddrinfo(result);

    if (aiSocket == INVALID_SOCKET) {
        // Silent failure - don't block UI
        return FALSE;
    }

    // Success - but don't show message to avoid blocking
    return TRUE;
}

// Disconnect from AI server
void DisconnectFromAIServer() {
    EnterCriticalSection(&aiCriticalSection);
    if (aiSocket != INVALID_SOCKET) {
        closesocket(aiSocket);
        aiSocket = INVALID_SOCKET;
    }
    LeaveCriticalSection(&aiCriticalSection);
}

// Parse AI command
BOOL ParseAICommand(char* buffer, AICommand* cmd) {
    if (buffer == NULL || cmd == NULL) {
        return FALSE;
    }
    
    char* token = strtok(buffer, ":");
    if (token == NULL) {
        return FALSE;
    }
    strncpy_s(cmd->command, sizeof(cmd->command), token, _TRUNCATE);
    
    token = strtok(NULL, "");
    if (token != NULL) {
        strncpy_s(cmd->parameters, sizeof(cmd->parameters), token, _TRUNCATE);
    } else {
        cmd->parameters[0] = '\0';
    }
    
    return TRUE;
}

// Execute AI command
// 辅助函数：解析内存地址
UINT_PTR ParseAddress(const char* addressStr) {
    if (addressStr == NULL) {
        return 0;
    }
    return (UINT_PTR)strtoull(addressStr, NULL, 16);
}

// 辅助函数：读取内存
BOOL ReadMemory(UINT_PTR address, char* type, void* buffer) {
    if (Exported.ReadProcessMemory == NULL) {
        return FALSE;
    }
    
    SIZE_T bytesRead;
    BOOL result = FALSE;
    
    if (strcmp(type, "byte") == 0 || strcmp(type, "BYTE") == 0) {
        result = (*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle, (LPCVOID)address, buffer, 1, &bytesRead);
    } else if (strcmp(type, "word") == 0 || strcmp(type, "WORD") == 0) {
        result = (*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle, (LPCVOID)address, buffer, 2, &bytesRead);
    } else if (strcmp(type, "dword") == 0 || strcmp(type, "DWORD") == 0) {
        result = (*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle, (LPCVOID)address, buffer, 4, &bytesRead);
    } else if (strcmp(type, "float") == 0 || strcmp(type, "FLOAT") == 0) {
        result = (*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle, (LPCVOID)address, buffer, 4, &bytesRead);
    } else if (strcmp(type, "double") == 0 || strcmp(type, "DOUBLE") == 0) {
        result = (*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle, (LPCVOID)address, buffer, 8, &bytesRead);
    } else if (strcmp(type, "int64") == 0 || strcmp(type, "INT64") == 0) {
        result = (*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle, (LPCVOID)address, buffer, 8, &bytesRead);
    } else if (strcmp(type, "string") == 0 || strcmp(type, "STRING") == 0) {
        // 读取字符串，最多256字节
        result = (*Exported.ReadProcessMemory)(*Exported.OpenedProcessHandle, (LPCVOID)address, buffer, 256, &bytesRead);
        if (result) {
            // 确保字符串以null结尾
            ((char*)buffer)[255] = '\0';
        }
    }
    
    return result && bytesRead > 0;
}

// 辅助函数：写入内存
BOOL WriteMemory(UINT_PTR address, const char* valueStr, const char* type) {
    if (Exported.WriteProcessMemory == NULL) {
        return FALSE;
    }
    
    // 定义WriteProcessMemory函数指针类型
    typedef BOOL(__stdcall *WriteProcessMemoryFunc)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
    WriteProcessMemoryFunc writeMem = (WriteProcessMemoryFunc)Exported.WriteProcessMemory;
    
    SIZE_T bytesWritten;
    BOOL result = FALSE;
    
    if (strcmp(type, "byte") == 0 || strcmp(type, "BYTE") == 0) {
        BYTE value = (BYTE)strtoul(valueStr, NULL, 0);
        result = writeMem(*Exported.OpenedProcessHandle, (LPVOID)address, &value, 1, &bytesWritten);
    } else if (strcmp(type, "word") == 0 || strcmp(type, "WORD") == 0) {
        WORD value = (WORD)strtoul(valueStr, NULL, 0);
        result = writeMem(*Exported.OpenedProcessHandle, (LPVOID)address, &value, 2, &bytesWritten);
    } else if (strcmp(type, "dword") == 0 || strcmp(type, "DWORD") == 0) {
        DWORD value = (DWORD)strtoul(valueStr, NULL, 0);
        result = writeMem(*Exported.OpenedProcessHandle, (LPVOID)address, &value, 4, &bytesWritten);
    } else if (strcmp(type, "float") == 0 || strcmp(type, "FLOAT") == 0) {
        float value = (float)atof(valueStr);
        result = writeMem(*Exported.OpenedProcessHandle, (LPVOID)address, &value, 4, &bytesWritten);
    } else if (strcmp(type, "double") == 0 || strcmp(type, "DOUBLE") == 0) {
        double value = atof(valueStr);
        result = writeMem(*Exported.OpenedProcessHandle, (LPVOID)address, &value, 8, &bytesWritten);
    } else if (strcmp(type, "int64") == 0 || strcmp(type, "INT64") == 0) {
        INT64 value = _strtoi64(valueStr, NULL, 0);
        result = writeMem(*Exported.OpenedProcessHandle, (LPVOID)address, &value, 8, &bytesWritten);
    } else if (strcmp(type, "string") == 0 || strcmp(type, "STRING") == 0) {
        // 写入字符串
        result = writeMem(*Exported.OpenedProcessHandle, (LPVOID)address, valueStr, strlen(valueStr) + 1, &bytesWritten);
    }
    
    return result && bytesWritten > 0;
}

void ExecuteAICommand(AICommand* cmd) {
    char message[1024];
    
    if (strcmp(cmd->command, "SHOW_MESSAGE") == 0) {
        Exported.ShowMessage(cmd->parameters);
    } else if (strcmp(cmd->command, "AUTO_ASSEMBLE") == 0) {
        BOOL result = Exported.AutoAssemble(cmd->parameters);
        sprintf_s(message, sizeof(message), "AutoAssemble result: %d", result);
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "SPEEDHACK") == 0) {
        float speed = atof(cmd->parameters);
        BOOL result = Exported.speedhack_setSpeed(speed);
        sprintf_s(message, sizeof(message), "SpeedHack result: %d, Speed: %.2f", result, speed);
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "PAUSE_PROCESS") == 0) {
        Exported.pause();
        Exported.ShowMessage("Process paused");
    } else if (strcmp(cmd->command, "UNPAUSE_PROCESS") == 0) {
        Exported.unpause();
        Exported.ShowMessage("Process unpaused");
    } else if (strcmp(cmd->command, "WRITE_MEMORY") == 0) {
        // 格式：WRITE_MEMORY:address,value,type
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            char* valueStr = strtok(NULL, ",");
            if (valueStr != NULL) {
                char* typeStr = strtok(NULL, ",");
                if (typeStr != NULL) {
                    UINT_PTR address = ParseAddress(addressStr);
                    BOOL result = WriteMemory(address, valueStr, typeStr);
                    sprintf_s(message, sizeof(message), "WriteMemory result: %d, Address: 0x%IX, Value: %s, Type: %s", 
                        result, address, valueStr, typeStr);
                    Exported.ShowMessage(message);
                } else {
                    Exported.ShowMessage("Error: Missing type parameter for WRITE_MEMORY");
                }
            } else {
                Exported.ShowMessage("Error: Missing value parameter for WRITE_MEMORY");
            }
        } else {
            Exported.ShowMessage("Error: Missing address parameter for WRITE_MEMORY");
        }
    } else if (strcmp(cmd->command, "READ_MEMORY") == 0) {
        // 格式：READ_MEMORY:address,type
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            char* typeStr = strtok(NULL, ",");
            if (typeStr != NULL) {
                UINT_PTR address = ParseAddress(addressStr);
                char buffer[256];
                BOOL result = ReadMemory(address, typeStr, buffer);
                if (result) {
                    if (strcmp(typeStr, "byte") == 0 || strcmp(typeStr, "BYTE") == 0) {
                        sprintf_s(message, sizeof(message), "ReadMemory result: %d, Address: 0x%IX, Value: 0x%02X, Type: %s", 
                            result, address, *(BYTE*)buffer, typeStr);
                    } else if (strcmp(typeStr, "word") == 0 || strcmp(typeStr, "WORD") == 0) {
                        sprintf_s(message, sizeof(message), "ReadMemory result: %d, Address: 0x%IX, Value: 0x%04X, Type: %s", 
                            result, address, *(WORD*)buffer, typeStr);
                    } else if (strcmp(typeStr, "dword") == 0 || strcmp(typeStr, "DWORD") == 0) {
                        sprintf_s(message, sizeof(message), "ReadMemory result: %d, Address: 0x%IX, Value: 0x%08X, Type: %s", 
                            result, address, *(DWORD*)buffer, typeStr);
                    } else if (strcmp(typeStr, "float") == 0 || strcmp(typeStr, "FLOAT") == 0) {
                        sprintf_s(message, sizeof(message), "ReadMemory result: %d, Address: 0x%IX, Value: %.6f, Type: %s", 
                            result, address, *(float*)buffer, typeStr);
                    } else if (strcmp(typeStr, "double") == 0 || strcmp(typeStr, "DOUBLE") == 0) {
                        sprintf_s(message, sizeof(message), "ReadMemory result: %d, Address: 0x%IX, Value: %.12f, Type: %s", 
                            result, address, *(double*)buffer, typeStr);
                    } else if (strcmp(typeStr, "int64") == 0 || strcmp(typeStr, "INT64") == 0) {
                        sprintf_s(message, sizeof(message), "ReadMemory result: %d, Address: 0x%IX, Value: 0x%016llX, Type: %s", 
                            result, address, *(INT64*)buffer, typeStr);
                    } else if (strcmp(typeStr, "string") == 0 || strcmp(typeStr, "STRING") == 0) {
                        sprintf_s(message, sizeof(message), "ReadMemory result: %d, Address: 0x%IX, Value: %s, Type: %s", 
                            result, address, buffer, typeStr);
                    } else {
                        sprintf_s(message, sizeof(message), "ReadMemory result: %d, Address: 0x%IX, Type: %s, Raw Value: %s", 
                            result, address, typeStr, buffer);
                    }
                    Exported.ShowMessage(message);
                } else {
                    sprintf_s(message, sizeof(message), "ReadMemory failed for Address: 0x%IX, Type: %s", address, typeStr);
                    Exported.ShowMessage(message);
                }
            } else {
                Exported.ShowMessage("Error: Missing type parameter for READ_MEMORY");
            }
        } else {
            Exported.ShowMessage("Error: Missing address parameter for READ_MEMORY");
        }
    } else if (strcmp(cmd->command, "ASSEMBLE") == 0) {
        // 格式：ASSEMBLE:address,instruction
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            char* instruction = strtok(NULL, ",");
            if (instruction != NULL) {
                UINT_PTR address = ParseAddress(addressStr);
                BYTE output[16]; // 最大支持16字节指令
                int returnedSize;
                BOOL result = Exported.Assembler(address, instruction, output, sizeof(output), &returnedSize);
                if (result) {
                    sprintf_s(message, sizeof(message), "ASSEMBLE result: %d, Address: 0x%IX, Instruction: %s\nMachine Code: ", 
                        result, address, instruction);
                    // 格式化机器码
                    char machineCode[64] = {0};
                    size_t machineCodeLen = 0;
                    for (int i = 0; i < returnedSize && machineCodeLen < sizeof(machineCode) - 3; i++) {
                        sprintf_s(machineCode + machineCodeLen, sizeof(machineCode) - machineCodeLen, "%02X ", output[i]);
                        machineCodeLen = strlen(machineCode);
                    }
                    strcat_s(message, sizeof(message), machineCode);
                    Exported.ShowMessage(message);
                } else {
                    sprintf_s(message, sizeof(message), "ASSEMBLE failed: Address: 0x%IX, Instruction: %s", address, instruction);
                    Exported.ShowMessage(message);
                }
            } else {
                Exported.ShowMessage("Error: Missing instruction parameter for ASSEMBLE");
            }
        } else {
            Exported.ShowMessage("Error: Missing address parameter for ASSEMBLE");
        }
    } else if (strcmp(cmd->command, "DISASSEMBLE") == 0) {
        // 格式：DISASSEMBLE:address
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            UINT_PTR address = ParseAddress(addressStr);
            char output[256];
            BOOL result = Exported.Disassembler(address, output, sizeof(output));
            if (result) {
                sprintf_s(message, sizeof(message), "DISASSEMBLE result: %d, Address: 0x%IX\nInstruction: %s", 
                    result, address, output);
                Exported.ShowMessage(message);
            } else {
                sprintf_s(message, sizeof(message), "DISASSEMBLE failed: Address: 0x%IX", address);
                Exported.ShowMessage(message);
            }
        } else {
            Exported.ShowMessage("Error: Missing address parameter for DISASSEMBLE");
        }
    } else if (strcmp(cmd->command, "DISASSEMBLE_EX") == 0) {
        // 格式：DISASSEMBLE_EX:address
        // 使用增强的反汇编功能，提供更详细的指令信息
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            UINT_PTR address = ParseAddress(addressStr);
            char output[512];
            BOOL result = Exported.disassembleEx(address, output, sizeof(output));
            if (result) {
                sprintf_s(message, sizeof(message), "DISASSEMBLE_EX result: %d, Address: 0x%IX\nInstruction: %s", 
                    result, address, output);
                Exported.ShowMessage(message);
            } else {
                sprintf_s(message, sizeof(message), "DISASSEMBLE_EX failed: Address: 0x%IX", address);
                Exported.ShowMessage(message);
            }
        } else {
            Exported.ShowMessage("Error: Missing address parameter for DISASSEMBLE_EX");
        }
    } else if (strcmp(cmd->command, "CHANGE_REGISTER") == 0) {
        // 格式：CHANGE_REGISTER:address,register_name,value
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            char* regName = strtok(NULL, ",");
            if (regName != NULL) {
                char* valueStr = strtok(NULL, ",");
                if (valueStr != NULL) {
                    UINT_PTR address = ParseAddress(addressStr);
                    UINT_PTR value = ParseAddress(valueStr);
                    
                    // 初始化寄存器修改结构体
                    REGISTERMODIFICATIONINFO changereg;
                    ZeroMemory(&changereg, sizeof(changereg));
                    changereg.address = address;
                    
                    // 设置要修改的寄存器
                    BOOL regSet = FALSE;
                    if (strcmp(regName, "eax") == 0 || strcmp(regName, "EAX") == 0) {
                        changereg.change_eax = TRUE;
                        changereg.new_eax = value;
                        regSet = TRUE;
                    } else if (strcmp(regName, "ebx") == 0 || strcmp(regName, "EBX") == 0) {
                        changereg.change_ebx = TRUE;
                        changereg.new_ebx = value;
                        regSet = TRUE;
                    } else if (strcmp(regName, "ecx") == 0 || strcmp(regName, "ECX") == 0) {
                        changereg.change_ecx = TRUE;
                        changereg.new_ecx = value;
                        regSet = TRUE;
                    } else if (strcmp(regName, "edx") == 0 || strcmp(regName, "EDX") == 0) {
                        changereg.change_edx = TRUE;
                        changereg.new_edx = value;
                        regSet = TRUE;
                    } else if (strcmp(regName, "esi") == 0 || strcmp(regName, "ESI") == 0) {
                        changereg.change_esi = TRUE;
                        changereg.new_esi = value;
                        regSet = TRUE;
                    } else if (strcmp(regName, "edi") == 0 || strcmp(regName, "EDI") == 0) {
                        changereg.change_edi = TRUE;
                        changereg.new_edi = value;
                        regSet = TRUE;
                    } else if (strcmp(regName, "ebp") == 0 || strcmp(regName, "EBP") == 0) {
                        changereg.change_ebp = TRUE;
                        changereg.new_ebp = value;
                        regSet = TRUE;
                    } else if (strcmp(regName, "esp") == 0 || strcmp(regName, "ESP") == 0) {
                        changereg.change_esp = TRUE;
                        changereg.new_esp = value;
                        regSet = TRUE;
                    } else if (strcmp(regName, "eip") == 0 || strcmp(regName, "EIP") == 0) {
                        changereg.change_eip = TRUE;
                        changereg.new_eip = value;
                        regSet = TRUE;
                    }
                    
                    if (regSet) {
                        BOOL result = Exported.ChangeRegistersAtAddress(address, &changereg);
                        sprintf_s(message, sizeof(message), "CHANGE_REGISTER result: %d, Address: 0x%IX, Register: %s, Value: 0x%IX", 
                            result, address, regName, value);
                        Exported.ShowMessage(message);
                    } else {
                        sprintf_s(message, sizeof(message), "CHANGE_REGISTER failed: Invalid register name: %s", regName);
                        Exported.ShowMessage(message);
                    }
                } else {
                    Exported.ShowMessage("Error: Missing value parameter for CHANGE_REGISTER");
                }
            } else {
                Exported.ShowMessage("Error: Missing register_name parameter for CHANGE_REGISTER");
            }
        } else {
            Exported.ShowMessage("Error: Missing address parameter for CHANGE_REGISTER");
        }
    } else if (strcmp(cmd->command, "INJECT_DLL") == 0) {
        // 格式：INJECT_DLL:dll_path,optional_function_name
        char* dllPath = strtok(cmd->parameters, ",");
        if (dllPath != NULL) {
            char* funcName = strtok(NULL, ",");
            if (funcName == NULL) {
                funcName = "";
            }
            
            BOOL result = Exported.InjectDLL(dllPath, funcName);
            sprintf_s(message, sizeof(message), "INJECT_DLL result: %d, DLL Path: %s, Function: %s", 
                result, dllPath, funcName);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing dll_path parameter for INJECT_DLL");
        }
    } else if (strcmp(cmd->command, "FREEZE_MEMORY") == 0) {
        // 格式：FREEZE_MEMORY:address,size
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            char* sizeStr = strtok(NULL, ",");
            if (sizeStr != NULL) {
                UINT_PTR address = ParseAddress(addressStr);
                int size = atoi(sizeStr);
                
                int freezeID = Exported.FreezeMem(address, size);
                sprintf_s(message, sizeof(message), "FREEZE_MEMORY result: freezeID = %d, Address: 0x%IX, Size: %d", 
                    freezeID, address, size);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing size parameter for FREEZE_MEMORY");
            }
        } else {
            Exported.ShowMessage("Error: Missing address parameter for FREEZE_MEMORY");
        }
    } else if (strcmp(cmd->command, "UNFREEZE_MEMORY") == 0) {
        // 格式：UNFREEZE_MEMORY:freeze_id
        char* freezeIDStr = strtok(cmd->parameters, ",");
        if (freezeIDStr != NULL) {
            int freezeID = atoi(freezeIDStr);
            BOOL result = Exported.UnfreezeMem(freezeID);
            sprintf_s(message, sizeof(message), "UNFREEZE_MEMORY result: %d, FreezeID: %d", result, freezeID);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing freeze_id parameter for UNFREEZE_MEMORY");
        }
    } else if (strcmp(cmd->command, "FIX_MEMORY") == 0) {
        // 格式：FIX_MEMORY
        BOOL result = Exported.FixMem();
        sprintf_s(message, sizeof(message), "FIX_MEMORY result: %d", result);
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "PROCESS_LIST") == 0) {
        // 格式：PROCESS_LIST
        char listBuffer[4096];
        BOOL result = Exported.ProcessList(listBuffer, sizeof(listBuffer));
        if (result) {
            sprintf_s(message, sizeof(message), "PROCESS_LIST result: %d\nProcess List:\n%s", result, listBuffer);
        } else {
            sprintf_s(message, sizeof(message), "PROCESS_LIST failed: result = %d", result);
        }
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "GET_PROCESS_ID") == 0) {
        // 格式：GET_PROCESS_ID:process_name
        char* processName = strtok(cmd->parameters, ",");
        if (processName != NULL) {
            DWORD processID = Exported.getProcessIDFromProcessName(processName);
            sprintf_s(message, sizeof(message), "GET_PROCESS_ID result: Process Name: %s, Process ID: %d", 
                processName, processID);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing process_name parameter for GET_PROCESS_ID");
        }
    } else if (strcmp(cmd->command, "OPEN_PROCESS") == 0) {
        // 格式：OPEN_PROCESS:process_id
        char* pidStr = strtok(cmd->parameters, ",");
        if (pidStr != NULL) {
            DWORD pid = atoi(pidStr);
            HANDLE processHandle = Exported.openProcessEx(pid);
            sprintf_s(message, sizeof(message), "OPEN_PROCESS result: Process ID: %d, Handle: 0x%p", 
                pid, processHandle);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing process_id parameter for OPEN_PROCESS");
        }
    } else if (strcmp(cmd->command, "GET_ADDRESS_FROM_POINTER") == 0) {
        // 格式：GET_ADDRESS_FROM_POINTER:base_address,offset_count,offset1,offset2,...
        char* baseAddrStr = strtok(cmd->parameters, ",");
        if (baseAddrStr != NULL) {
            char* offsetCountStr = strtok(NULL, ",");
            if (offsetCountStr != NULL) {
                UINT_PTR baseAddress = ParseAddress(baseAddrStr);
                int offsetCount = atoi(offsetCountStr);
                
                if (offsetCount > 0 && offsetCount <= 16) {
                    int offsets[16];
                    int i;
                    BOOL valid = TRUE;
                    
                    for (i = 0; i < offsetCount; i++) {
                        char* offsetStr = strtok(NULL, ",");
                        if (offsetStr != NULL) {
                            offsets[i] = (int)strtol(offsetStr, NULL, 0);
                        } else {
                            valid = FALSE;
                            break;
                        }
                    }
                    
                    if (valid) {
                        UINT_PTR finalAddress = Exported.GetAddressFromPointer(baseAddress, offsetCount, offsets);
                        sprintf_s(message, sizeof(message), "GET_ADDRESS_FROM_POINTER result: Base: 0x%IX, Final: 0x%IX", 
                            baseAddress, finalAddress);
                        Exported.ShowMessage(message);
                    } else {
                        Exported.ShowMessage("Error: Invalid offset parameters for GET_ADDRESS_FROM_POINTER");
                    }
                } else {
                    Exported.ShowMessage("Error: Invalid offset count for GET_ADDRESS_FROM_POINTER (1-16)");
                }
            } else {
                Exported.ShowMessage("Error: Missing offset_count parameter for GET_ADDRESS_FROM_POINTER");
            }
        } else {
            Exported.ShowMessage("Error: Missing base_address parameter for GET_ADDRESS_FROM_POINTER");
        }
    } else if (strcmp(cmd->command, "ADDRESS_TO_NAME") == 0) {
        // 格式：ADDRESS_TO_NAME:address
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            UINT_PTR address = ParseAddress(addressStr);
            char name[256];
            BOOL result = Exported.sym_addressToName(address, name, sizeof(name));
            if (result) {
                sprintf_s(message, sizeof(message), "ADDRESS_TO_NAME result: Address: 0x%IX, Name: %s", address, name);
            } else {
                sprintf_s(message, sizeof(message), "ADDRESS_TO_NAME result: Address: 0x%IX, Name: <not found>", address);
            }
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing address parameter for ADDRESS_TO_NAME");
        }
    } else if (strcmp(cmd->command, "NAME_TO_ADDRESS") == 0) {
        // 格式：NAME_TO_ADDRESS:name
        char* name = strtok(cmd->parameters, ",");
        if (name != NULL) {
            UINT_PTR address;
            BOOL result = Exported.sym_nameToAddress(name, &address);
            if (result) {
                sprintf_s(message, sizeof(message), "NAME_TO_ADDRESS result: Name: %s, Address: 0x%IX", name, address);
            } else {
                sprintf_s(message, sizeof(message), "NAME_TO_ADDRESS result: Name: %s, Address: <not found>", name);
            }
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing name parameter for NAME_TO_ADDRESS");
        }
    } else if (strcmp(cmd->command, "PREVIOUS_OPCODE") == 0) {
        // 格式：PREVIOUS_OPCODE:address
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            UINT_PTR address = ParseAddress(addressStr);
            DWORD prevAddr = Exported.previousOpcode(address);
            sprintf_s(message, sizeof(message), "PREVIOUS_OPCODE result: Current: 0x%IX, Previous: 0x%IX", address, prevAddr);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing address parameter for PREVIOUS_OPCODE");
        }
    } else if (strcmp(cmd->command, "NEXT_OPCODE") == 0) {
        // 格式：NEXT_OPCODE:address
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            UINT_PTR address = ParseAddress(addressStr);
            DWORD nextAddr = Exported.nextOpcode(address);
            sprintf_s(message, sizeof(message), "NEXT_OPCODE result: Current: 0x%IX, Next: 0x%IX", address, nextAddr);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing address parameter for NEXT_OPCODE");
        }
    } else if (strcmp(cmd->command, "SET_BREAKPOINT") == 0) {
        // 格式：SET_BREAKPOINT:address,size,trigger
        // trigger: 0=execute, 1=write, 2=read
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            char* sizeStr = strtok(NULL, ",");
            if (sizeStr != NULL) {
                char* triggerStr = strtok(NULL, ",");
                if (triggerStr != NULL) {
                    UINT_PTR address = ParseAddress(addressStr);
                    int size = atoi(sizeStr);
                    int trigger = atoi(triggerStr);
                    
                    BOOL result = Exported.debug_setBreakpoint(address, size, trigger);
                    sprintf_s(message, sizeof(message), "SET_BREAKPOINT result: %d, Address: 0x%IX, Size: %d, Trigger: %d", 
                        result, address, size, trigger);
                    Exported.ShowMessage(message);
                } else {
                    Exported.ShowMessage("Error: Missing trigger parameter for SET_BREAKPOINT");
                }
            } else {
                Exported.ShowMessage("Error: Missing size parameter for SET_BREAKPOINT");
            }
        } else {
            Exported.ShowMessage("Error: Missing address parameter for SET_BREAKPOINT");
        }
    } else if (strcmp(cmd->command, "REMOVE_BREAKPOINT") == 0) {
        // 格式：REMOVE_BREAKPOINT:address
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            UINT_PTR address = ParseAddress(addressStr);
            BOOL result = Exported.debug_removeBreakpoint(address);
            sprintf_s(message, sizeof(message), "REMOVE_BREAKPOINT result: %d, Address: 0x%IX", result, address);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing address parameter for REMOVE_BREAKPOINT");
        }
    } else if (strcmp(cmd->command, "CONTINUE_FROM_BREAKPOINT") == 0) {
        // 格式：CONTINUE_FROM_BREAKPOINT:continue_option
        // continue_option: 0=run, 1=step into, 2=step over, 3=step to return
        char* optionStr = strtok(cmd->parameters, ",");
        if (optionStr != NULL) {
            int option = atoi(optionStr);
            BOOL result = Exported.debug_continueFromBreakpoint(option);
            sprintf_s(message, sizeof(message), "CONTINUE_FROM_BREAKPOINT result: %d, Option: %d", result, option);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing continue_option parameter for CONTINUE_FROM_BREAKPOINT");
        }
    } else if (strcmp(cmd->command, "CREATE_TABLE_ENTRY") == 0) {
        // 格式：CREATE_TABLE_ENTRY
        PVOID memrec = Exported.createTableEntry();
        sprintf_s(message, sizeof(message), "CREATE_TABLE_ENTRY result: MemRec pointer = 0x%p", memrec);
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "GET_TABLE_ENTRY") == 0) {
        // 格式：GET_TABLE_ENTRY:description
        char* description = strtok(cmd->parameters, ",");
        if (description != NULL) {
            PVOID memrec = Exported.getTableEntry(description);
            sprintf_s(message, sizeof(message), "GET_TABLE_ENTRY result: Description = %s, MemRec pointer = 0x%p", description, memrec);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing description parameter for GET_TABLE_ENTRY");
        }
    } else if (strcmp(cmd->command, "MEMREC_SETDESCRIPTION") == 0) {
        // 格式：MEMREC_SETDESCRIPTION:memrec_pointer,description
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            char* description = strtok(NULL, ",");
            if (description != NULL) {
                PVOID memrec = (PVOID)ParseAddress(memrecStr);
                BOOL result = Exported.memrec_setDescription(memrec, description);
                sprintf_s(message, sizeof(message), "MEMREC_SETDESCRIPTION result: %d, MemRec: 0x%p, Description: %s", result, memrec, description);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing description parameter for MEMREC_SETDESCRIPTION");
            }
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_SETDESCRIPTION");
        }
    } else if (strcmp(cmd->command, "MEMREC_GETDESCRIPTION") == 0) {
        // 格式：MEMREC_GETDESCRIPTION:memrec_pointer
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            PVOID memrec = (PVOID)ParseAddress(memrecStr);
            char* description = Exported.memrec_getDescription(memrec);
            sprintf_s(message, sizeof(message), "MEMREC_GETDESCRIPTION result: MemRec: 0x%p, Description: %s", memrec, description ? description : "<null>");
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_GETDESCRIPTION");
        }
    } else if (strcmp(cmd->command, "MEMREC_GETADDRESS") == 0) {
        // 格式：MEMREC_GETADDRESS:memrec_pointer
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            PVOID memrec = (PVOID)ParseAddress(memrecStr);
            UINT_PTR address;
            DWORD offsets[16];
            int neededOffsets;
            BOOL result = Exported.memrec_getAddress(memrec, &address, offsets, 16, &neededOffsets);
            if (result) {
                sprintf_s(message, sizeof(message), "MEMREC_GETADDRESS result: MemRec: 0x%p, Address: 0x%IX, Offsets needed: %d", memrec, address, neededOffsets);
            } else {
                sprintf_s(message, sizeof(message), "MEMREC_GETADDRESS failed: MemRec: 0x%p", memrec);
            }
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_GETADDRESS");
        }
    } else if (strcmp(cmd->command, "MEMREC_SETADDRESS") == 0) {
        // 格式：MEMREC_SETADDRESS:memrec_pointer,address,offset_count,offset1,offset2,...
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            char* addressStr = strtok(NULL, ",");
            if (addressStr != NULL) {
                char* offsetCountStr = strtok(NULL, ",");
                if (offsetCountStr != NULL) {
                    PVOID memrec = (PVOID)ParseAddress(memrecStr);
                    UINT_PTR address = ParseAddress(addressStr);
                    int offsetCount = atoi(offsetCountStr);
                    
                    if (offsetCount >= 0 && offsetCount <= 16) {
                        DWORD offsets[16] = {0};
                        for (int i = 0; i < offsetCount; i++) {
                            char* offsetStr = strtok(NULL, ",");
                            if (offsetStr != NULL) {
                                offsets[i] = (DWORD)strtol(offsetStr, NULL, 0);
                            }
                        }
                        
                        BOOL result = Exported.memrec_setAddress(memrec, addressStr, offsets, offsetCount);
                        sprintf_s(message, sizeof(message), "MEMREC_SETADDRESS result: %d, MemRec: 0x%p, Address: 0x%IX, Offset count: %d", result, memrec, address, offsetCount);
                        Exported.ShowMessage(message);
                    } else {
                        Exported.ShowMessage("Error: Invalid offset count for MEMREC_SETADDRESS (0-16)");
                    }
                } else {
                    Exported.ShowMessage("Error: Missing offset_count parameter for MEMREC_SETADDRESS");
                }
            } else {
                Exported.ShowMessage("Error: Missing address parameter for MEMREC_SETADDRESS");
            }
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_SETADDRESS");
        }
    } else if (strcmp(cmd->command, "MEMREC_GETTYPE") == 0) {
        // 格式：MEMREC_GETTYPE:memrec_pointer
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            PVOID memrec = (PVOID)ParseAddress(memrecStr);
            int vtype = Exported.memrec_getType(memrec);
            sprintf_s(message, sizeof(message), "MEMREC_GETTYPE result: MemRec: 0x%p, Type: %d", memrec, vtype);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_GETTYPE");
        }
    } else if (strcmp(cmd->command, "MEMREC_SETTYPE") == 0) {
        // 格式：MEMREC_SETTYPE:memrec_pointer,vtype
        // vtype: 0=byte, 1=word, 2=dword, 3=float, 4=double, 5=bit, 6=int64, 7=string
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            char* vtypeStr = strtok(NULL, ",");
            if (vtypeStr != NULL) {
                PVOID memrec = (PVOID)ParseAddress(memrecStr);
                int vtype = atoi(vtypeStr);
                BOOL result = Exported.memrec_setType(memrec, vtype);
                sprintf_s(message, sizeof(message), "MEMREC_SETTYPE result: %d, MemRec: 0x%p, Type: %d", result, memrec, vtype);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing vtype parameter for MEMREC_SETTYPE");
            }
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_SETTYPE");
        }
    } else if (strcmp(cmd->command, "MEMREC_GETVALUE") == 0) {
        // 格式：MEMREC_GETVALUE:memrec_pointer
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            PVOID memrec = (PVOID)ParseAddress(memrecStr);
            char value[256];
            BOOL result = Exported.memrec_getValue(memrec, value, sizeof(value));
            if (result) {
                sprintf_s(message, sizeof(message), "MEMREC_GETVALUE result: MemRec: 0x%p, Value: %s", memrec, value);
            } else {
                sprintf_s(message, sizeof(message), "MEMREC_GETVALUE failed: MemRec: 0x%p", memrec);
            }
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_GETVALUE");
        }
    } else if (strcmp(cmd->command, "MEMREC_SETVALUE") == 0) {
        // 格式：MEMREC_SETVALUE:memrec_pointer,value
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            char* value = strtok(NULL, ",");
            if (value != NULL) {
                PVOID memrec = (PVOID)ParseAddress(memrecStr);
                BOOL result = Exported.memrec_setValue(memrec, value);
                sprintf_s(message, sizeof(message), "MEMREC_SETVALUE result: %d, MemRec: 0x%p, Value: %s", result, memrec, value);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing value parameter for MEMREC_SETVALUE");
            }
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_SETVALUE");
        }
    } else if (strcmp(cmd->command, "MEMREC_GETSCRIPT") == 0) {
        // 格式：MEMREC_GETSCRIPT:memrec_pointer
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            PVOID memrec = (PVOID)ParseAddress(memrecStr);
            char* script = Exported.memrec_getScript(memrec);
            sprintf_s(message, sizeof(message), "MEMREC_GETSCRIPT result: MemRec: 0x%p, Script: %s", memrec, script ? script : "<null>");
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_GETSCRIPT");
        }
    } else if (strcmp(cmd->command, "MEMREC_SETSCRIPT") == 0) {
        // 格式：MEMREC_SETSCRIPT:memrec_pointer,script
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            char* script = strtok(NULL, ",");
            if (script != NULL) {
                PVOID memrec = (PVOID)ParseAddress(memrecStr);
                BOOL result = Exported.memrec_setScript(memrec, script);
                sprintf_s(message, sizeof(message), "MEMREC_SETSCRIPT result: %d, MemRec: 0x%p", result, memrec);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing script parameter for MEMREC_SETSCRIPT");
            }
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_SETSCRIPT");
        }
    } else if (strcmp(cmd->command, "MEMREC_ISFROZEN") == 0) {
        // 格式：MEMREC_ISFROZEN:memrec_pointer
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            PVOID memrec = (PVOID)ParseAddress(memrecStr);
            BOOL isFrozen = Exported.memrec_isfrozen(memrec);
            sprintf_s(message, sizeof(message), "MEMREC_ISFROZEN result: MemRec: 0x%p, IsFrozen: %d", memrec, isFrozen);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_ISFROZEN");
        }
    } else if (strcmp(cmd->command, "MEMREC_FREEZE") == 0) {
        // 格式：MEMREC_FREEZE:memrec_pointer,direction
        // direction: 0=frozen, 1=increase, 2=decrease
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            char* directionStr = strtok(NULL, ",");
            if (directionStr != NULL) {
                PVOID memrec = (PVOID)ParseAddress(memrecStr);
                int direction = atoi(directionStr);
                BOOL result = Exported.memrec_freeze(memrec, direction);
                sprintf_s(message, sizeof(message), "MEMREC_FREEZE result: %d, MemRec: 0x%p, Direction: %d", result, memrec, direction);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing direction parameter for MEMREC_FREEZE");
            }
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_FREEZE");
        }
    } else if (strcmp(cmd->command, "MEMREC_UNFREEZE") == 0) {
        // 格式：MEMREC_UNFREEZE:memrec_pointer
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            PVOID memrec = (PVOID)ParseAddress(memrecStr);
            BOOL result = Exported.memrec_unfreeze(memrec);
            sprintf_s(message, sizeof(message), "MEMREC_UNFREEZE result: %d, MemRec: 0x%p", result, memrec);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_UNFREEZE");
        }
    } else if (strcmp(cmd->command, "MEMREC_SETCOLOR") == 0) {
        // 格式：MEMREC_SETCOLOR:memrec_pointer,color
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            char* colorStr = strtok(NULL, ",");
            if (colorStr != NULL) {
                PVOID memrec = (PVOID)ParseAddress(memrecStr);
                DWORD color = (DWORD)strtol(colorStr, NULL, 0);
                BOOL result = Exported.memrec_setColor(memrec, color);
                sprintf_s(message, sizeof(message), "MEMREC_SETCOLOR result: %d, MemRec: 0x%p, Color: 0x%08X", result, memrec, color);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing color parameter for MEMREC_SETCOLOR");
            }
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_SETCOLOR");
        }
    } else if (strcmp(cmd->command, "MEMREC_APPENDTOENTRY") == 0) {
        // 格式：MEMREC_APPENDTOENTRY:memrec_pointer1,memrec_pointer2
        char* memrecStr1 = strtok(cmd->parameters, ",");
        if (memrecStr1 != NULL) {
            char* memrecStr2 = strtok(NULL, ",");
            if (memrecStr2 != NULL) {
                PVOID memrec1 = (PVOID)ParseAddress(memrecStr1);
                PVOID memrec2 = (PVOID)ParseAddress(memrecStr2);
                BOOL result = Exported.memrec_appendtoentry(memrec1, memrec2);
                sprintf_s(message, sizeof(message), "MEMREC_APPENDTOENTRY result: %d, MemRec1: 0x%p, MemRec2: 0x%p", result, memrec1, memrec2);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing memrec_pointer2 parameter for MEMREC_APPENDTOENTRY");
            }
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer1 parameter for MEMREC_APPENDTOENTRY");
        }
    } else if (strcmp(cmd->command, "MEMREC_DELETE") == 0) {
        // 格式：MEMREC_DELETE:memrec_pointer
        char* memrecStr = strtok(cmd->parameters, ",");
        if (memrecStr != NULL) {
            PVOID memrec = (PVOID)ParseAddress(memrecStr);
            BOOL result = Exported.memrec_delete(memrec);
            sprintf_s(message, sizeof(message), "MEMREC_DELETE result: %d, MemRec: 0x%p", result, memrec);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing memrec_pointer parameter for MEMREC_DELETE");
        }
    } else if (strcmp(cmd->command, "CLOSE_CE") == 0) {
        // 格式：CLOSE_CE
        Exported.closeCE();
        sprintf_s(message, sizeof(message), "CLOSE_CE executed");
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "HIDE_ALL_CE_WINDOWS") == 0) {
        // 格式：HIDE_ALL_CE_WINDOWS
        Exported.hideAllCEWindows();
        sprintf_s(message, sizeof(message), "HIDE_ALL_CE_WINDOWS executed");
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "UNHIDE_MAIN_CE_WINDOW") == 0) {
        // 格式：UNHIDE_MAIN_CE_WINDOW
        Exported.unhideMainCEwindow();
        sprintf_s(message, sizeof(message), "UNHIDE_MAIN_CE_WINDOW executed");
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "GET_MAIN_WINDOW_HANDLE") == 0) {
        // 格式：GET_MAIN_WINDOW_HANDLE
        HANDLE hwnd = Exported.GetMainWindowHandle();
        sprintf_s(message, sizeof(message), "GET_MAIN_WINDOW_HANDLE result: HWND = 0x%p", hwnd);
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "MESSAGE_DIALOG") == 0) {
        // 格式：MESSAGE_DIALOG:message,messagetype,buttoncombination
        // messagetype: 0=mtWarning, 1=mtError, 2=mtInformation, 3=mtConfirmation
        // buttoncombination: 0=mbOK, 1=mbOKCancel, 2=mbYesNo, 3=mbYesNoCancel
        char* msgText = strtok(cmd->parameters, ",");
        if (msgText != NULL) {
            char* msgTypeStr = strtok(NULL, ",");
            if (msgTypeStr != NULL) {
                char* btnComboStr = strtok(NULL, ",");
                if (btnComboStr != NULL) {
                    int msgType = atoi(msgTypeStr);
                    int btnCombo = atoi(btnComboStr);
                    int result = Exported.messageDialog(msgText, msgType, btnCombo);
                    sprintf_s(message, sizeof(message), "MESSAGE_DIALOG result: %d, Message: %s, Type: %d, Buttons: %d", result, msgText, msgType, btnCombo);
                    Exported.ShowMessage(message);
                } else {
                    Exported.ShowMessage("Error: Missing buttoncombination parameter for MESSAGE_DIALOG");
                }
            } else {
                Exported.ShowMessage("Error: Missing messagetype parameter for MESSAGE_DIALOG");
            }
        } else {
            Exported.ShowMessage("Error: Missing message parameter for MESSAGE_DIALOG");
        }
    } else if (strcmp(cmd->command, "LOAD_MODULE") == 0) {
        // 格式：LOAD_MODULE:module_path
        char* modulePath = strtok(cmd->parameters, ",");
        if (modulePath != NULL) {
            char exportList[4096];
            int maxSize = sizeof(exportList);
            BOOL result = Exported.loadModule(modulePath, exportList, &maxSize);
            if (result) {
                sprintf_s(message, sizeof(message), "LOAD_MODULE result: %d, Module: %s\nExport List: %s", result, modulePath, exportList);
            } else {
                sprintf_s(message, sizeof(message), "LOAD_MODULE failed: Module: %s", modulePath);
            }
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing module_path parameter for LOAD_MODULE");
        }
    } else if (strcmp(cmd->command, "GENERATE_API_HOOK_SCRIPT") == 0) {
        // 格式：GENERATE_API_HOOK_SCRIPT:address,addresstojumpto,addresstogetnewcalladdress
        char* addressStr = strtok(cmd->parameters, ",");
        if (addressStr != NULL) {
            char* jumpToAddrStr = strtok(NULL, ",");
            if (jumpToAddrStr != NULL) {
                char* newCallAddrStr = strtok(NULL, ",");
                if (newCallAddrStr != NULL) {
                    char script[4096];
                    BOOL result = Exported.sym_generateAPIHookScript(addressStr, jumpToAddrStr, newCallAddrStr, script, sizeof(script));
                    if (result) {
                        sprintf_s(message, sizeof(message), "GENERATE_API_HOOK_SCRIPT result: %d\nScript:\n%s", result, script);
                    } else {
                        sprintf_s(message, sizeof(message), "GENERATE_API_HOOK_SCRIPT failed: Address: %s", addressStr);
                    }
                    Exported.ShowMessage(message);
                } else {
                    Exported.ShowMessage("Error: Missing addresstogetnewcalladdress parameter for GENERATE_API_HOOK_SCRIPT");
                }
            } else {
                Exported.ShowMessage("Error: Missing addresstojumpto parameter for GENERATE_API_HOOK_SCRIPT");
            }
        } else {
            Exported.ShowMessage("Error: Missing address parameter for GENERATE_API_HOOK_SCRIPT");
        }
    } else if (strcmp(cmd->command, "DEBUG_PROCESS") == 0) {
        // 格式：DEBUG_PROCESS:debuggerinterface
        // debuggerinterface: 0=windows debugger, 1=veh debugger, 2=kernel debugger
        char* debuggerInterfaceStr = strtok(cmd->parameters, ",");
        if (debuggerInterfaceStr != NULL) {
            int debuggerInterface = atoi(debuggerInterfaceStr);
            DWORD result = Exported.debugProcessEx(debuggerInterface);
            sprintf_s(message, sizeof(message), "DEBUG_PROCESS result: %d, Debugger Interface: %d", result, debuggerInterface);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing debuggerinterface parameter for DEBUG_PROCESS");
        }
    } else if (strcmp(cmd->command, "AA_ADD_COMMAND") == 0) {
        // 格式：AA_ADD_COMMAND:command
        char* command = strtok(cmd->parameters, ",");
        if (command != NULL) {
            Exported.aa_AddExtraCommand(command);
            sprintf_s(message, sizeof(message), "AA_ADD_COMMAND executed: %s", command);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing command parameter for AA_ADD_COMMAND");
        }
    } else if (strcmp(cmd->command, "AA_DEL_COMMAND") == 0) {
        // 格式：AA_DEL_COMMAND:command
        char* command = strtok(cmd->parameters, ",");
        if (command != NULL) {
            Exported.aa_RemoveExtraCommand(command);
            sprintf_s(message, sizeof(message), "AA_DEL_COMMAND executed: %s", command);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing command parameter for AA_DEL_COMMAND");
        }
    } else if (strcmp(cmd->command, "CREATE_FORM") == 0) {
        // 格式：CREATE_FORM
        PVOID form = Exported.createForm();
        sprintf_s(message, sizeof(message), "CREATE_FORM result: Form pointer = 0x%p", form);
        Exported.ShowMessage(message);
    } else if (strcmp(cmd->command, "CREATE_PANEL") == 0) {
        // 格式：CREATE_PANEL:owner_pointer
        char* ownerStr = strtok(cmd->parameters, ",");
        if (ownerStr != NULL) {
            PVOID owner = (PVOID)ParseAddress(ownerStr);
            PVOID panel = Exported.createPanel(owner);
            sprintf_s(message, sizeof(message), "CREATE_PANEL result: Owner: 0x%p, Panel pointer = 0x%p", owner, panel);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing owner_pointer parameter for CREATE_PANEL");
        }
    } else if (strcmp(cmd->command, "CREATE_LABEL") == 0) {
        // 格式：CREATE_LABEL:owner_pointer
        char* ownerStr = strtok(cmd->parameters, ",");
        if (ownerStr != NULL) {
            PVOID owner = (PVOID)ParseAddress(ownerStr);
            PVOID label = Exported.createLabel(owner);
            sprintf_s(message, sizeof(message), "CREATE_LABEL result: Owner: 0x%p, Label pointer = 0x%p", owner, label);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing owner_pointer parameter for CREATE_LABEL");
        }
    } else if (strcmp(cmd->command, "CREATE_EDIT") == 0) {
        // 格式：CREATE_EDIT:owner_pointer
        char* ownerStr = strtok(cmd->parameters, ",");
        if (ownerStr != NULL) {
            PVOID owner = (PVOID)ParseAddress(ownerStr);
            PVOID edit = Exported.createEdit(owner);
            sprintf_s(message, sizeof(message), "CREATE_EDIT result: Owner: 0x%p, Edit pointer = 0x%p", owner, edit);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing owner_pointer parameter for CREATE_EDIT");
        }
    } else if (strcmp(cmd->command, "CREATE_BUTTON") == 0) {
        // 格式：CREATE_BUTTON:owner_pointer
        char* ownerStr = strtok(cmd->parameters, ",");
        if (ownerStr != NULL) {
            PVOID owner = (PVOID)ParseAddress(ownerStr);
            PVOID button = Exported.createButton(owner);
            sprintf_s(message, sizeof(message), "CREATE_BUTTON result: Owner: 0x%p, Button pointer = 0x%p", owner, button);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing owner_pointer parameter for CREATE_BUTTON");
        }
    } else if (strcmp(cmd->command, "CREATE_IMAGE") == 0) {
        // 格式：CREATE_IMAGE:owner_pointer
        char* ownerStr = strtok(cmd->parameters, ",");
        if (ownerStr != NULL) {
            PVOID owner = (PVOID)ParseAddress(ownerStr);
            PVOID image = Exported.createImage(owner);
            sprintf_s(message, sizeof(message), "CREATE_IMAGE result: Owner: 0x%p, Image pointer = 0x%p", owner, image);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing owner_pointer parameter for CREATE_IMAGE");
        }
    } else if (strcmp(cmd->command, "SET_CAPTION") == 0) {
        // 格式：SET_CAPTION:control_pointer,caption
        char* controlStr = strtok(cmd->parameters, ",");
        if (controlStr != NULL) {
            char* caption = strtok(NULL, ",");
            if (caption != NULL) {
                PVOID control = (PVOID)ParseAddress(controlStr);
                Exported.control_setCaption(control, caption);
                sprintf_s(message, sizeof(message), "SET_CAPTION executed: Control: 0x%p, Caption: %s", control, caption);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing caption parameter for SET_CAPTION");
            }
        } else {
            Exported.ShowMessage("Error: Missing control_pointer parameter for SET_CAPTION");
        }
    } else if (strcmp(cmd->command, "GET_CAPTION") == 0) {
        // 格式：GET_CAPTION:control_pointer
        char* controlStr = strtok(cmd->parameters, ",");
        if (controlStr != NULL) {
            PVOID control = (PVOID)ParseAddress(controlStr);
            char caption[256];
            BOOL result = Exported.control_getCaption(control, caption, sizeof(caption));
            if (result) {
                sprintf_s(message, sizeof(message), "GET_CAPTION result: Control: 0x%p, Caption: %s", control, caption);
            } else {
                sprintf_s(message, sizeof(message), "GET_CAPTION failed: Control: 0x%p", control);
            }
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing control_pointer parameter for GET_CAPTION");
        }
    } else if (strcmp(cmd->command, "SET_POSITION") == 0) {
        // 格式：SET_POSITION:control_pointer,x,y
        char* controlStr = strtok(cmd->parameters, ",");
        if (controlStr != NULL) {
            char* xStr = strtok(NULL, ",");
            if (xStr != NULL) {
                char* yStr = strtok(NULL, ",");
                if (yStr != NULL) {
                    PVOID control = (PVOID)ParseAddress(controlStr);
                    int x = atoi(xStr);
                    int y = atoi(yStr);
                    Exported.control_setPosition(control, x, y);
                    sprintf_s(message, sizeof(message), "SET_POSITION executed: Control: 0x%p, X: %d, Y: %d", control, x, y);
                    Exported.ShowMessage(message);
                } else {
                    Exported.ShowMessage("Error: Missing y parameter for SET_POSITION");
                }
            } else {
                Exported.ShowMessage("Error: Missing x parameter for SET_POSITION");
            }
        } else {
            Exported.ShowMessage("Error: Missing control_pointer parameter for SET_POSITION");
        }
    } else if (strcmp(cmd->command, "GET_POSITION") == 0) {
        // 格式：GET_POSITION:control_pointer
        char* controlStr = strtok(cmd->parameters, ",");
        if (controlStr != NULL) {
            PVOID control = (PVOID)ParseAddress(controlStr);
            int x = Exported.control_getX(control);
            int y = Exported.control_getY(control);
            sprintf_s(message, sizeof(message), "GET_POSITION result: Control: 0x%p, X: %d, Y: %d", control, x, y);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing control_pointer parameter for GET_POSITION");
        }
    } else if (strcmp(cmd->command, "SET_SIZE") == 0) {
        // 格式：SET_SIZE:control_pointer,width,height
        char* controlStr = strtok(cmd->parameters, ",");
        if (controlStr != NULL) {
            char* widthStr = strtok(NULL, ",");
            if (widthStr != NULL) {
                char* heightStr = strtok(NULL, ",");
                if (heightStr != NULL) {
                    PVOID control = (PVOID)ParseAddress(controlStr);
                    int width = atoi(widthStr);
                    int height = atoi(heightStr);
                    Exported.control_setSize(control, width, height);
                    sprintf_s(message, sizeof(message), "SET_SIZE executed: Control: 0x%p, Width: %d, Height: %d", control, width, height);
                    Exported.ShowMessage(message);
                } else {
                    Exported.ShowMessage("Error: Missing height parameter for SET_SIZE");
                }
            } else {
                Exported.ShowMessage("Error: Missing width parameter for SET_SIZE");
            }
        } else {
            Exported.ShowMessage("Error: Missing control_pointer parameter for SET_SIZE");
        }
    } else if (strcmp(cmd->command, "GET_SIZE") == 0) {
        // 格式：GET_SIZE:control_pointer
        char* controlStr = strtok(cmd->parameters, ",");
        if (controlStr != NULL) {
            PVOID control = (PVOID)ParseAddress(controlStr);
            int width = Exported.control_getWidth(control);
            int height = Exported.control_getHeight(control);
            sprintf_s(message, sizeof(message), "GET_SIZE result: Control: 0x%p, Width: %d, Height: %d", control, width, height);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing control_pointer parameter for GET_SIZE");
        }
    } else if (strcmp(cmd->command, "DESTROY_OBJECT") == 0) {
        // 格式：DESTROY_OBJECT:object_pointer
        char* objectStr = strtok(cmd->parameters, ",");
        if (objectStr != NULL) {
            PVOID object = (PVOID)ParseAddress(objectStr);
            Exported.object_destroy(object);
            sprintf_s(message, sizeof(message), "DESTROY_OBJECT executed: Object: 0x%p", object);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing object_pointer parameter for DESTROY_OBJECT");
        }
    } else if (strcmp(cmd->command, "FORM_CENTER_SCREEN") == 0) {
        // 格式：FORM_CENTER_SCREEN:form_pointer
        char* formStr = strtok(cmd->parameters, ",");
        if (formStr != NULL) {
            PVOID form = (PVOID)ParseAddress(formStr);
            Exported.form_centerScreen(form);
            sprintf_s(message, sizeof(message), "FORM_CENTER_SCREEN executed: Form: 0x%p", form);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing form_pointer parameter for FORM_CENTER_SCREEN");
        }
    } else if (strcmp(cmd->command, "FORM_HIDE") == 0) {
        // 格式：FORM_HIDE:form_pointer
        char* formStr = strtok(cmd->parameters, ",");
        if (formStr != NULL) {
            PVOID form = (PVOID)ParseAddress(formStr);
            Exported.form_hide(form);
            sprintf_s(message, sizeof(message), "FORM_HIDE executed: Form: 0x%p", form);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing form_pointer parameter for FORM_HIDE");
        }
    } else if (strcmp(cmd->command, "FORM_SHOW") == 0) {
        // 格式：FORM_SHOW:form_pointer
        char* formStr = strtok(cmd->parameters, ",");
        if (formStr != NULL) {
            PVOID form = (PVOID)ParseAddress(formStr);
            Exported.form_show(form);
            sprintf_s(message, sizeof(message), "FORM_SHOW executed: Form: 0x%p", form);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing form_pointer parameter for FORM_SHOW");
        }
    } else if (strcmp(cmd->command, "IMAGE_LOAD_IMAGE_FROM_FILE") == 0) {
        // 格式：IMAGE_LOAD_IMAGE_FROM_FILE:image_pointer,filename
        char* imageStr = strtok(cmd->parameters, ",");
        if (imageStr != NULL) {
            char* filename = strtok(NULL, ",");
            if (filename != NULL) {
                PVOID image = (PVOID)ParseAddress(imageStr);
                BOOL result = Exported.image_loadImageFromFile(image, filename);
                sprintf_s(message, sizeof(message), "IMAGE_LOAD_IMAGE_FROM_FILE result: %d, Image: 0x%p, Filename: %s", result, image, filename);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing filename parameter for IMAGE_LOAD_IMAGE_FROM_FILE");
            }
        } else {
            Exported.ShowMessage("Error: Missing image_pointer parameter for IMAGE_LOAD_IMAGE_FROM_FILE");
        }
    } else if (strcmp(cmd->command, "IMAGE_TRANSPARENT") == 0) {
        // 格式：IMAGE_TRANSPARENT:image_pointer,transparent
        char* imageStr = strtok(cmd->parameters, ",");
        if (imageStr != NULL) {
            char* transparentStr = strtok(NULL, ",");
            if (transparentStr != NULL) {
                PVOID image = (PVOID)ParseAddress(imageStr);
                BOOL transparent = (atoi(transparentStr) != 0);
                Exported.image_transparent(image, transparent);
                sprintf_s(message, sizeof(message), "IMAGE_TRANSPARENT executed: Image: 0x%p, Transparent: %d", image, transparent);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing transparent parameter for IMAGE_TRANSPARENT");
            }
        } else {
            Exported.ShowMessage("Error: Missing image_pointer parameter for IMAGE_TRANSPARENT");
        }
    } else if (strcmp(cmd->command, "IMAGE_STRETCH") == 0) {
        // 格式：IMAGE_STRETCH:image_pointer,stretch
        char* imageStr = strtok(cmd->parameters, ",");
        if (imageStr != NULL) {
            char* stretchStr = strtok(NULL, ",");
            if (stretchStr != NULL) {
                PVOID image = (PVOID)ParseAddress(imageStr);
                BOOL stretch = (atoi(stretchStr) != 0);
                Exported.image_stretch(image, stretch);
                sprintf_s(message, sizeof(message), "IMAGE_STRETCH executed: Image: 0x%p, Stretch: %d", image, stretch);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing stretch parameter for IMAGE_STRETCH");
            }
        } else {
            Exported.ShowMessage("Error: Missing image_pointer parameter for IMAGE_STRETCH");
        }
    } else if (strcmp(cmd->command, "CREATE_TIMER") == 0) {
        // 格式：CREATE_TIMER:owner_pointer
        char* ownerStr = strtok(cmd->parameters, ",");
        if (ownerStr != NULL) {
            PVOID owner = (PVOID)ParseAddress(ownerStr);
            PVOID timer = Exported.createTimer(owner);
            sprintf_s(message, sizeof(message), "CREATE_TIMER result: Owner: 0x%p, Timer pointer = 0x%p", owner, timer);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing owner_pointer parameter for CREATE_TIMER");
        }
    } else if (strcmp(cmd->command, "TIMER_SET_INTERVAL") == 0) {
        // 格式：TIMER_SET_INTERVAL:timer_pointer,interval
        char* timerStr = strtok(cmd->parameters, ",");
        if (timerStr != NULL) {
            char* intervalStr = strtok(NULL, ",");
            if (intervalStr != NULL) {
                PVOID timer = (PVOID)ParseAddress(timerStr);
                int interval = atoi(intervalStr);
                Exported.timer_setInterval(timer, interval);
                sprintf_s(message, sizeof(message), "TIMER_SET_INTERVAL executed: Timer: 0x%p, Interval: %d ms", timer, interval);
                Exported.ShowMessage(message);
            } else {
                Exported.ShowMessage("Error: Missing interval parameter for TIMER_SET_INTERVAL");
            }
        } else {
            Exported.ShowMessage("Error: Missing timer_pointer parameter for TIMER_SET_INTERVAL");
        }
    } else if (strcmp(cmd->command, "CREATE_MEMO") == 0) {
        // 格式：CREATE_MEMO:owner_pointer
        char* ownerStr = strtok(cmd->parameters, ",");
        if (ownerStr != NULL) {
            PVOID owner = (PVOID)ParseAddress(ownerStr);
            PVOID memo = Exported.createMemo(owner);
            sprintf_s(message, sizeof(message), "CREATE_MEMO result: Owner: 0x%p, Memo pointer = 0x%p", owner, memo);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing owner_pointer parameter for CREATE_MEMO");
        }
    } else if (strcmp(cmd->command, "CREATE_GROUP_BOX") == 0) {
        // 格式：CREATE_GROUP_BOX:owner_pointer
        char* ownerStr = strtok(cmd->parameters, ",");
        if (ownerStr != NULL) {
            PVOID owner = (PVOID)ParseAddress(ownerStr);
            PVOID groupbox = Exported.createGroupBox(owner);
            sprintf_s(message, sizeof(message), "CREATE_GROUP_BOX result: Owner: 0x%p, GroupBox pointer = 0x%p", owner, groupbox);
            Exported.ShowMessage(message);
        } else {
            Exported.ShowMessage("Error: Missing owner_pointer parameter for CREATE_GROUP_BOX");
        }
    } else {
        sprintf_s(message, sizeof(message), "Unknown command: %s", cmd->command);
        Exported.ShowMessage(message);
    }
}

// AI communication thread
DWORD WINAPI AICommunicationThread(LPVOID lpParam) {
    char recvBuffer[1024];
    int iResult;
    
    // Try to connect to AI server
    if (!ConnectToAIServer()) {
        // Connection failed, but continue running the thread
        // It will retry when isRunning is TRUE
    }
    
    while (isRunning) {
        // Receive data from AI server
        EnterCriticalSection(&aiCriticalSection);
        SOCKET currentSocket = aiSocket;
        LeaveCriticalSection(&aiCriticalSection);
        
        if (currentSocket == INVALID_SOCKET) {
            Sleep(100);
            continue;
        }
        
        iResult = recv(currentSocket, recvBuffer, sizeof(recvBuffer) - 1, 0);
        if (iResult > 0) {
            recvBuffer[iResult] = '\0';
            
            // Parse and execute command
            AICommand cmd;
            if (ParseAICommand(recvBuffer, &cmd)) {
                ExecuteAICommand(&cmd);
            }
        } else if (iResult == 0) {
            // Connection closed by server
            EnterCriticalSection(&aiCriticalSection);
            closesocket(aiSocket);
            aiSocket = INVALID_SOCKET;
            LeaveCriticalSection(&aiCriticalSection);
        } else {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                // Connection error, close socket
                EnterCriticalSection(&aiCriticalSection);
                closesocket(aiSocket);
                aiSocket = INVALID_SOCKET;
                LeaveCriticalSection(&aiCriticalSection);
            }
        }
        
        // Sleep to reduce CPU usage
        Sleep(100);
    }
    
    return 0;
}

// Main menu plugin callback
void __stdcall mainmenuplugin(void) {
    Exported.ShowMessage("CE-MCP-Plugin Main Menu");
    return;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Initialize Winsock when DLL is loaded
            InitWinsock();
            // Note: Critical section will be initialized in CEPlugin_InitializePlugin
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
            
        case DLL_PROCESS_DETACH:
            // Cleanup Winsock when DLL is unloaded
            CleanupWinsock();
            // Delete critical section if it was initialized
            // Note: It will be deleted in CEPlugin_DisablePlugin
            break;
    }
    
    return TRUE;
}

BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int sizeofpluginversion) {
    pv->version = CESDK_VERSION;
    pv->pluginname = "CE-MCP-Plugin v1.0 (SDK version 6: 7.0+)";
    return TRUE;
}

// Lua function to send command to AI
int lua_aiSendCommand(lua_State* L) {
    if (lua_gettop(L) < 1) {
        lua_pushstring(L, "Error: Missing command parameter");
        return 1;
    }
    
    const char* command = lua_tostring(L, 1);
    if (command == NULL) {
        lua_pushstring(L, "Error: Invalid command");
        return 1;
    }
    
    EnterCriticalSection(&aiCriticalSection);
    SOCKET currentSocket = aiSocket;
    LeaveCriticalSection(&aiCriticalSection);
    
    if (currentSocket == INVALID_SOCKET) {
        lua_pushstring(L, "Error: Not connected to AI server");
        return 1;
    }
    
    int iResult = send(currentSocket, command, (int)strlen(command), 0);
    if (iResult == SOCKET_ERROR) {
        lua_pushstring(L, "Error: Failed to send command");
        return 1;
    }
    
    lua_pushstring(L, "Command sent successfully");
    return 1;
}

BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions ef, int pluginid) {
    MAINMENUPLUGIN_INIT init5;

    selfid = pluginid;
    
    // Copy the ExportedFunctions list
    Exported = *ef;
    if (Exported.sizeofExportedFunctions != sizeof(Exported)) {
        return FALSE;
    }

    // Initialize critical section for thread synchronization
    InitializeCriticalSection(&aiCriticalSection);

    // Register main menu plugin
    init5.name = "CE-MCP-Plugin";
    init5.callbackroutine = mainmenuplugin;
    init5.shortcut = "Ctrl+A";
    
    int mainMenuPluginID = Exported.RegisterFunction(pluginid, ptMainMenu, &init5);
    if (mainMenuPluginID == -1) {
        // Silent failure - don't block CE initialization
        DeleteCriticalSection(&aiCriticalSection);
        return FALSE;
    }
    
    // Register Lua functions
    lua_State* lua_state = ef->GetLuaState();
    if (lua_state != NULL) {
        lua_register(lua_state, "aiSendCommand", lua_aiSendCommand);
    }
    // If Lua state is NULL, silently continue without Lua support
    
    // Start AI communication thread (connection will be attempted in the thread)
    EnterCriticalSection(&aiCriticalSection);
    isRunning = TRUE;
    aiThread = CreateThread(NULL, 0, AICommunicationThread, NULL, 0, NULL);
    LeaveCriticalSection(&aiCriticalSection);
    
    if (aiThread == NULL) {
        // Silent failure - don't block CE initialization
        isRunning = FALSE;
    }
    
    // Plugin enabled successfully - silent, no UI message to avoid blocking
    return TRUE;
}

BOOL __stdcall CEPlugin_DisablePlugin(void) {
    // Stop AI communication thread
    EnterCriticalSection(&aiCriticalSection);
    isRunning = FALSE;
    LeaveCriticalSection(&aiCriticalSection);
    
    if (aiThread != NULL) {
        DWORD waitResult = WaitForSingleObject(aiThread, 5000);
        if (waitResult == WAIT_TIMEOUT) {
            // Thread is still running, but we'll proceed with cleanup
            // Don't show message to avoid blocking
        } else if (waitResult == WAIT_FAILED) {
            // Don't show message to avoid blocking
        }
        CloseHandle(aiThread);
        aiThread = NULL;
    }
    
    // Disconnect from AI server
    DisconnectFromAIServer();
    
    // Delete critical section
    DeleteCriticalSection(&aiCriticalSection);
    
    // Plugin disabled successfully - silent, no UI message to avoid blocking
    return TRUE;
}

