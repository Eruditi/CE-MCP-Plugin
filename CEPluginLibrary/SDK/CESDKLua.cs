using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CESDK
{
    public class CESDKLua
    {
        private IntPtr lua_state;
        private CESDK sdk;
        private delegate int delegate_luaRegister(IntPtr L, string name, IntPtr func);
        private delegate int delegate_luaGetTop(IntPtr L);
        private delegate void delegate_luaPop(IntPtr L, int i);
        private delegate bool delegate_luaIsInteger(IntPtr L, int index);
        private delegate long delegate_luaToInteger(IntPtr L, int index);
        private delegate void delegate_luaPushInteger(IntPtr L, long i);
        private delegate void delegate_luaPushString(IntPtr L, string s);
        private delegate void delegate_luaDoString(IntPtr L, string s);
        private delegate bool delegate_luaIsFunction(IntPtr L, int index);
        private delegate int delegate_luaPcall(IntPtr L, int nargs, int nresults, int errfunc);
        private delegate void delegate_luaGetGlobal(IntPtr L, string name);

        private delegate_luaRegister _luaRegister;
        private delegate_luaGetTop _luaGetTop;
        private delegate_luaPop _luaPop;
        private delegate_luaIsInteger _luaIsInteger;
        private delegate_luaToInteger _luaToInteger;
        private delegate_luaPushInteger _luaPushInteger;
        private delegate_luaPushString _luaPushString;
        private delegate_luaDoString _luaDoString;
        private delegate_luaIsFunction _luaIsFunction;
        private delegate_luaPcall _luaPcall;
        private delegate_luaGetGlobal _luaGetGlobal;

        public CESDKLua(CESDK sdk)
        {
            this.sdk = sdk;
            lua_state = sdk.pluginexports.GetLuaState;

            // Get function pointers from the exported functions
            IntPtr luaRegisterPtr = sdk.pluginexports.LuaRegister;
            _luaRegister = Marshal.GetDelegateForFunctionPointer<delegate_luaRegister>(luaRegisterPtr);

            // Note: For other Lua functions, we'll use the Lua C API directly via DllImport
        }

        // Lua C API imports
        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int lua_gettop(IntPtr L);

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void lua_pop(IntPtr L, int n);

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool lua_isinteger(IntPtr L, int idx);

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern long lua_tointeger(IntPtr L, int idx);

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void lua_pushinteger(IntPtr L, long n);

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void lua_pushstring(IntPtr L, string s);

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int luaL_dostring(IntPtr L, string s);

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool lua_isfunction(IntPtr L, int idx);

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int lua_pcall(IntPtr L, int nargs, int nresults, int errfunc);

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void lua_getglobal(IntPtr L, string name);

        // Public methods for Lua interaction
        public int GetTop()
        {
            return lua_gettop(lua_state);
        }

        public void Pop(int n)
        {
            lua_pop(lua_state, n);
        }

        public bool IsInteger(int index)
        {
            return lua_isinteger(lua_state, index);
        }

        public long ToInteger(int index)
        {
            return lua_tointeger(lua_state, index);
        }

        public void PushInteger(long value)
        {
            lua_pushinteger(lua_state, value);
        }

        public void PushInteger(IntPtr L, long value)
        {
            lua_pushinteger(L, value);
        }

        public void PushString(string value)
        {
            lua_pushstring(lua_state, value);
        }

        public void PushString(IntPtr L, string value)
        {
            lua_pushstring(L, value);
        }

        public void DoString(string code)
        {
            luaL_dostring(lua_state, code);
        }

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr lua_tostring(IntPtr L, int idx);

        /// <summary>
        /// Get string value from Lua stack
        /// </summary>
        /// <param name="index">Stack index</param>
        /// <returns>String value</returns>
        public string ToString(int index)
        {
            IntPtr strPtr = lua_tostring(lua_state, index);
            if (strPtr == IntPtr.Zero)
                return null;
            
            return Marshal.PtrToStringAnsi(strPtr);
        }

        [DllImport("lua53.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool lua_isstring(IntPtr L, int idx);

        /// <summary>
        /// Check if value at index is a string
        /// </summary>
        /// <param name="index">Stack index</param>
        /// <returns>True if it's a string, false otherwise</returns>
        public bool IsString(int index)
        {
            return lua_isstring(lua_state, index);
        }

        public bool IsFunction(int index)
        {
            return lua_isfunction(lua_state, index);
        }

        public int PCall(int nargs, int nresults, int errfunc)
        {
            return lua_pcall(lua_state, nargs, nresults, errfunc);
        }

        public void GetGlobal(string name)
        {
            lua_getglobal(lua_state, name);
        }

        // Register a C# function to Lua
        public void Register(string name, Delegate func)
        {
            IntPtr funcPtr = Marshal.GetFunctionPointerForDelegate(func);
            _luaRegister(lua_state, name, funcPtr);
        }
    }
}