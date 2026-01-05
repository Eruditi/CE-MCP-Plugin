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
        Exported.ShowMessage("getaddrinfo failed");
        return FALSE;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        // Create a SOCKET for connecting to server
        aiSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (aiSocket == INVALID_SOCKET) {
            Exported.ShowMessage("socket failed");
            // Don't freeaddrinfo here, we'll do it after the loop
            continue;
        }

        // Set socket to non-blocking mode for timeout
        u_long mode = 1;
        if (ioctlsocket(aiSocket, FIONBIO, &mode) == SOCKET_ERROR) {
            Exported.ShowMessage("ioctlsocket failed to set non-blocking mode");
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
                // Connection timeout
                closesocket(aiSocket);
                aiSocket = INVALID_SOCKET;
                Exported.ShowMessage("Connection to AI server timed out");
                continue;
            } else if (iResult == SOCKET_ERROR) {
                int selectError = WSAGetLastError();
                char errorMsg[128];
                sprintf_s(errorMsg, sizeof(errorMsg), "select failed with error: %d", selectError);
                Exported.ShowMessage(errorMsg);
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
            Exported.ShowMessage("ioctlsocket failed to set blocking mode");
            closesocket(aiSocket);
            aiSocket = INVALID_SOCKET;
            freeaddrinfo(result);
            return FALSE;
        }
        
        break;
    }

    freeaddrinfo(result);

    if (aiSocket == INVALID_SOCKET) {
        Exported.ShowMessage("Failed to connect to AI server");
        return FALSE;
    }

    Exported.ShowMessage("Connected to AI server");
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
    } else {
        sprintf_s(message, sizeof(message), "Unknown command: %s", cmd->command);
        Exported.ShowMessage(message);
    }
}

// AI communication thread
DWORD WINAPI AICommunicationThread(LPVOID lpParam) {
    char recvBuffer[1024];
    int iResult;
    
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
            Exported.ShowMessage("Connection to AI server closed");
            break;
        } else {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                Exported.ShowMessage("recv failed");
                break;
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
            // Initialize critical section for thread synchronization
            InitializeCriticalSection(&aiCriticalSection);
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
            
        case DLL_PROCESS_DETACH:
            // Cleanup Winsock when DLL is unloaded
            CleanupWinsock();
            // Delete critical section
            DeleteCriticalSection(&aiCriticalSection);
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

    // Register main menu plugin
    init5.name = "CE-MCP-Plugin";
    init5.callbackroutine = mainmenuplugin;
    init5.shortcut = "Ctrl+A";
    
    int mainMenuPluginID = Exported.RegisterFunction(pluginid, ptMainMenu, &init5);
    if (mainMenuPluginID == -1) {
        Exported.ShowMessage("Failed to register main menu plugin");
        return FALSE;
    }
    
    // Register Lua functions
    lua_State* lua_state = ef->GetLuaState();
    if (lua_state != NULL) {
        lua_register(lua_state, "aiSendCommand", lua_aiSendCommand);
    } else {
        Exported.ShowMessage("Warning: Failed to get Lua state, Lua functions will not be available");
    }
    
    // Connect to AI server
    if (ConnectToAIServer()) {
        // Start AI communication thread
        EnterCriticalSection(&aiCriticalSection);
        isRunning = TRUE;
        aiThread = CreateThread(NULL, 0, AICommunicationThread, NULL, 0, NULL);
        LeaveCriticalSection(&aiCriticalSection);
        
        if (aiThread == NULL) {
            Exported.ShowMessage("Failed to create AI communication thread");
            isRunning = FALSE;
            DisconnectFromAIServer();
            return FALSE;
        }
    }
    
    Exported.ShowMessage("CE-MCP-Plugin enabled");
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
            Exported.ShowMessage("Warning: AI communication thread did not stop gracefully");
            // Thread is still running, but we'll proceed with cleanup
        } else if (waitResult == WAIT_FAILED) {
            Exported.ShowMessage("Warning: Failed to wait for AI communication thread");
        }
        CloseHandle(aiThread);
        aiThread = NULL;
    }
    
    // Disconnect from AI server
    DisconnectFromAIServer();
    
    Exported.ShowMessage("CE-MCP-Plugin disabled");
    return TRUE;
}

