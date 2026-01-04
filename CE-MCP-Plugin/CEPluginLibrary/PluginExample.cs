using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using CESDK;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace CEPluginLibrary
{
    class PluginExample : CESDKPluginClass
    {
        // Plugin version information
        private const string PLUGIN_VERSION = "1.0.0";
        private const string CE_MIN_VERSION = "7.1";
        
        // Log file path
        private string logFilePath;
        
        // Plugin state
        private bool isInitialized = false;
        
        // Resource management
        private List<string> tempFiles = new List<string>();
        
        // Configuration
        private Configuration config;
        
        // Local HTTP Server
        private LocalHttpServer localHttpServer;
        
        // Thread management
        private Thread mcpServerThread;
        private Process mcpServerProcess;
        private CancellationTokenSource cts;
        
        public override string GetPluginName()
        {
            return $"CE MCP Plugin v{PLUGIN_VERSION} (Cheat Engine Model Context Protocol)";
        }

        public override bool DisablePlugin() //called when disabled
        {
            Log("Disabling plugin...");
            
            // Stop MCP server when plugin is disabled
            StopMCPServer();
            
            // Stop local HTTP server
            if (localHttpServer != null)
            {
                try
                {
                    localHttpServer.Stop();
                    localHttpServer = null;
                }
                catch (Exception ex)
                {
                    Log("Error stopping local HTTP server: " + ex.Message, LogLevel.Error);
                }
            }
            
            // Cleanup resources
            CleanupResources();
            
            Log("Plugin disabled");
            return true;
        }
        
        public override bool EnablePlugin() //called when enabled
        {
            try
            {
                Log("Enabling plugin...");
                
                // Initialize plugin
                InitializePlugin();
                
                // Validate Cheat Engine version
                if (!ValidateCEVersion())
                {
                    Log("Error: Cheat Engine version too old. Minimum required: " + CE_MIN_VERSION, LogLevel.Error);
                    return false;
                }
                
                // Register Lua functions with error handling
                try
                {
                    sdk.lua.Register("startMCPServer", StartMCPServer);
                    sdk.lua.Register("stopMCPServer", StopMCPServer);
                    sdk.lua.Register("showPluginSettings", ShowPluginSettings);
                    Log("Lua functions registered successfully");
                }
                catch (Exception ex)
                {
                    Log("Error registering Lua functions: " + ex.Message, LogLevel.Error);
                    return false;
                }

                // Add menu items
                try
                {
                    string menuScript = @"local m=MainForm.Menu
local topm=createMenuItem(m)
topm.Caption='CE MCP Plugin v" + PLUGIN_VERSION + @"'
m.Items.insert(MainForm.miHelp.MenuIndex,topm)

local mf1=createMenuItem(m)
mf1.Caption='Start MCP Server';
mf1.OnClick=function(s)
  local result = startMCPServer()
  if result == 1 then
    print('MCP Server started successfully')
  elseif result == 0 then
    print('MCP Server is already running')
  else
    print('Failed to start MCP Server')
  end
end
topm.add(mf1)

local mf2=createMenuItem(m)
mf2.Caption='Stop MCP Server';
mf2.OnClick=function(s)
  local result = stopMCPServer()
  if result == 1 then
    print('MCP Server stopped successfully')
  elseif result == 0 then
    print('MCP Server is not running')
  else
    print('Failed to stop MCP Server')
  end
end
topm.add(mf2)

local mf3=createMenuItem(m)
mf3.Caption='Plugin Settings';
mf3.OnClick=function(s)
  showPluginSettings()
end
topm.add(mf3)";
                    
                    sdk.lua.DoString(menuScript);
                    Log("Menu items added successfully");
                }
                catch (Exception ex)
                {
                    Log("Error adding menu items: " + ex.Message, LogLevel.Error);
                    return false;
                }

                // Start local HTTP server for Python communication
                try
                {
                    localHttpServer = new LocalHttpServer(this);
                    localHttpServer.Start();
                    Log("Local HTTP server started successfully");
                }
                catch (Exception ex)
                {
                    Log("Error starting local HTTP server: " + ex.Message, LogLevel.Error);
                    return false;
                }

                Log("Plugin enabled successfully");
                return true;            
            }
            catch (Exception ex)
            {
                Log("Error enabling plugin: " + ex.Message, LogLevel.Error);
                return false;
            }
        }
        
        /// <summary>
        /// Initialize plugin resources
        /// </summary>
        private void InitializePlugin()
        {
            if (isInitialized)
                return;
                
            // Load configuration
            config = Configuration.Load();
            
            // Initialize log file
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string cePluginPath = Path.Combine(appDataPath, "Cheat Engine", "Plugins", "CEMCPPlugin");
            Directory.CreateDirectory(cePluginPath);
            logFilePath = Path.Combine(cePluginPath, "plugin.log");
            
            // Clear old log file if it's too large
            if (File.Exists(logFilePath))
            {
                FileInfo logFile = new FileInfo(logFilePath);
                if (logFile.Length > 1024 * 1024) // 1MB
                {
                    File.Delete(logFilePath);
                }
            }
            
            Log("Plugin initialized");
            Log($"Loaded configuration: Port={config.Port}, LogLevel={config.LogLevel}, EnableHttps={config.EnableHttps}, EnableAuthentication={config.EnableAuthentication}", LogLevel.Debug);
            isInitialized = true;
        }
        
        /// <summary>
        /// Validate Cheat Engine version
        /// </summary>
        /// <returns>True if CE version is compatible</returns>
        private bool ValidateCEVersion()
        {
            try
            {
                // This would need to be implemented to check actual CE version
                // For now, assume it's compatible
                return true;
            }
            catch (Exception ex)
            {
                Log("Error validating CE version: " + ex.Message, LogLevel.Warning);
                return true; // Assume compatible if we can't check
            }
        }
        
        /// <summary>
        /// Log levels
        /// </summary>
        private enum LogLevel
        {
            Info,
            Warning,
            Error,
            Debug
        }
        
        /// <summary>
        /// Log message to file and CE console
        /// </summary>
        /// <param name="message">Message to log</param>
        /// <param name="level">Log level</param>
        private void Log(string message, LogLevel level = LogLevel.Info)
        {
            try
            {
                // Check if logging is enabled for this level
                if (!IsLoggingEnabled(level))
                    return;
                
                // Format log message with timestamp, level, thread ID, and message
                string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] [Thread:{Thread.CurrentThread.ManagedThreadId}] {message}{Environment.NewLine}";
                
                // Write to log file (thread-safe)
                if (!string.IsNullOrEmpty(logFilePath))
                {
                    // Use File.AppendAllText which is thread-safe
                    File.AppendAllText(logFilePath, logEntry);
                }
                
                // Write to CE console (ensure thread safety)
                LogToCEConsole(level, message);
            }
            catch { /* Ignore logging errors to prevent cascading failures */ }
        }
        
        /// <summary>
        /// Check if logging is enabled for the specified level
        /// </summary>
        /// <param name="level">Log level to check</param>
        /// <returns>True if logging is enabled for this level</returns>
        private bool IsLoggingEnabled(LogLevel level)
        {
            // Map log level string to enum
            LogLevel configLevel = LogLevel.Info;
            if (!string.IsNullOrEmpty(config.LogLevel))
            {
                try
                {
                    configLevel = (LogLevel)Enum.Parse(typeof(LogLevel), config.LogLevel, true);
                }
                catch { /* Ignore parsing errors, default to Info */ }
            }
            
            // Return true if the message level is >= config level
            return level >= configLevel;
        }
        
        /// <summary>
        /// Thread-safe logging to CE console
        /// </summary>
        /// <param name="level">Log level</param>
        /// <param name="message">Message to log</param>
        private void LogToCEConsole(LogLevel level, string message)
        {
            try
            {
                // Format message for CE console
                string consoleMessage = $"[{level}] {message}";
                
                // Use a thread-safe way to execute Lua commands
                // CESDK's DoString is not guaranteed to be thread-safe, so we'll use a lock
                lock (this)
                {
                    // Escape single quotes in the message
                    string escapedMessage = consoleMessage.Replace("'", "''");
                    sdk.lua.DoString($"print('{escapedMessage}')");
                }
            }
            catch { /* Ignore console logging errors */ }
        }
        
        /// <summary>
        /// Cleanup plugin resources
        /// </summary>
        private void CleanupResources()
        {
            Log("Cleaning up resources...");
            
            // Cleanup temp files
            foreach (string tempFile in tempFiles)
            {
                try
                {
                    if (File.Exists(tempFile))
                    {
                        File.Delete(tempFile);
                        Log("Deleted temp file: " + tempFile);
                    }
                }
                catch (Exception ex)
                {
                    Log("Error deleting temp file " + tempFile + ": " + ex.Message, LogLevel.Warning);
                }
            }
            tempFiles.Clear();
            
            // Reset plugin state
            isInitialized = false;
            
            Log("Resources cleaned up");
        }
        
        int StartMCPServer()
        {
            try
            {
                Log("Starting MCP server...");
                
                if (mcpServerThread == null || !mcpServerThread.IsAlive)
                {
                    // Create cancellation token source
                    cts = new CancellationTokenSource();
                    
                    mcpServerThread = new Thread(() => RunMCPServer(cts.Token));
                    mcpServerThread.IsBackground = true;
                    mcpServerThread.Name = "CE MCPServer Thread";
                    mcpServerThread.Start();
                    
                    Log("MCP server thread started successfully");
                    sdk.lua.PushInteger(1); // Success
                }
                else
                {
                    Log("MCP server is already running", LogLevel.Warning);
                    sdk.lua.PushInteger(0); // Already running
                }
            }
            catch (Exception ex)
            {
                string errorMsg = "Failed to start MCP server: " + ex.Message;
                Log(errorMsg, LogLevel.Error);
                
                sdk.lua.PushInteger(-1); // Error
                sdk.lua.PushString(errorMsg);
                return 2;
            }
            return 1;
        }

        int StopMCPServer()
        {
            try
            {
                Log("Stopping MCP server...");
                
                bool success = false;
                
                // Cancel the token to signal the thread to stop
                if (cts != null)
                {
                    try
                    {
                        cts.Cancel();
                        cts.Dispose();
                        cts = null;
                    }
                    catch (Exception ex)
                    {
                        Log("Error canceling token: " + ex.Message, LogLevel.Error);
                    }
                }
                
                // Stop the MCP server process if it's running
                if (mcpServerProcess != null && !mcpServerProcess.HasExited)
                {
                    try
                    {
                        mcpServerProcess.Kill();
                        if (mcpServerProcess.WaitForExit(5000)) // Wait up to 5 seconds
                        {
                            mcpServerProcess.Dispose();
                            mcpServerProcess = null;
                            success = true;
                            Log("MCP server process stopped successfully");
                        }
                        else
                        {
                            Log("Warning: MCP server process did not exit within timeout", LogLevel.Warning);
                            mcpServerProcess.Dispose();
                            mcpServerProcess = null;
                            success = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        Log("Error stopping MCP server process: " + ex.Message, LogLevel.Error);
                    }
                }
                
                // Wait for the thread to exit gracefully
                if (mcpServerThread != null && mcpServerThread.IsAlive)
                {
                    try
                    {
                        if (mcpServerThread.Join(3000)) // Wait up to 3 seconds
                        {
                            mcpServerThread = null;
                            success = true;
                            Log("MCP server thread stopped successfully");
                        }
                        else
                        {
                            Log("Warning: MCP server thread did not exit within timeout", LogLevel.Warning);
                            mcpServerThread = null;
                            success = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        Log("Error stopping MCP server thread: " + ex.Message, LogLevel.Error);
                    }
                }
                
                if (success)
                {
                    Log("MCP server stopped successfully");
                    sdk.lua.PushInteger(1); // Success
                }
                else
                {
                    Log("MCP server was not running", LogLevel.Info);
                    sdk.lua.PushInteger(0); // Not running
                }
            }
            catch (Exception ex)
            {
                string errorMsg = "Failed to stop MCP server: " + ex.Message;
                Log(errorMsg, LogLevel.Error);
                
                sdk.lua.PushInteger(-1); // Error
                sdk.lua.PushString(errorMsg);
                return 2;
            }
            return 1;
        }

        /// <summary>
        /// Check if Python is available with timeout
        /// </summary>
        /// <returns>True if Python is available, False otherwise</returns>
        private bool IsPythonAvailable(int timeoutMs = 2000)
        {
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "python";
                startInfo.Arguments = "--version";
                startInfo.UseShellExecute = false;
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;
                startInfo.CreateNoWindow = true;

                using (Process process = new Process())
                {
                    process.StartInfo = startInfo;
                    process.Start();
                    
                    // Wait for process to exit with timeout
                    bool exited = process.WaitForExit(timeoutMs);
                    
                    return exited && process.ExitCode == 0;
                }
            }
            catch (Exception ex)
            {
                Log("Error checking Python availability: " + ex.Message, LogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// Check if fastmcp library is installed with timeout
        /// </summary>
        /// <returns>True if fastmcp is installed, False otherwise</returns>
        private bool IsFastMCPInstalled(int timeoutMs = 2000)
        {
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "python";
                startInfo.Arguments = "-c \"import fastmcp\"";
                startInfo.UseShellExecute = false;
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;
                startInfo.CreateNoWindow = true;

                using (Process process = new Process())
                {
                    process.StartInfo = startInfo;
                    process.Start();
                    
                    // Wait for process to exit with timeout
                    bool exited = process.WaitForExit(timeoutMs);
                    
                    return exited && process.ExitCode == 0;
                }
            }
            catch (Exception ex)
            {
                Log("Error checking fastmcp availability: " + ex.Message, LogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// Install fastmcp library with timeout and proper resource management
        /// </summary>
        /// <returns>True if installation succeeded, False otherwise</returns>
        private bool InstallFastMCP(int timeoutMs = 30000)
        {
            try
            {
                Log("Installing fastmcp library...");

                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "python";
                startInfo.Arguments = "-m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple fastmcp";
                startInfo.UseShellExecute = false;
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;
                startInfo.CreateNoWindow = true;

                using (Process process = new Process())
                {
                    process.StartInfo = startInfo;
                    process.Start();

                    // Read output asynchronously to avoid deadlocks
                    StringBuilder outputBuilder = new StringBuilder();
                    StringBuilder errorBuilder = new StringBuilder();
                    
                    // Start async output reading
                    process.OutputDataReceived += (sender, e) =>
                    {
                        if (e.Data != null)
                            outputBuilder.AppendLine(e.Data);
                    };
                    
                    process.ErrorDataReceived += (sender, e) =>
                    {
                        if (e.Data != null)
                            errorBuilder.AppendLine(e.Data);
                    };
                    
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    // Wait for process to exit with timeout
                    bool exited = process.WaitForExit(timeoutMs);
                    
                    string output = outputBuilder.ToString();
                    string error = errorBuilder.ToString();
                    
                    if (exited)
                    {
                        if (process.ExitCode == 0)
                        {
                            Log("fastmcp library installed successfully");
                            return true;
                        }
                        else
                        {
                            Log($"Failed to install fastmcp library (exit code: {process.ExitCode}). Output: {output}. Error: {error}", LogLevel.Error);
                            return false;
                        }
                    }
                    else
                    {
                        Log($"Fastmcp installation timed out after {timeoutMs}ms. Output: {output}. Error: {error}", LogLevel.Error);
                        process.Kill();
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Error installing fastmcp library: " + ex.Message, LogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// Show plugin settings dialog
        /// </summary>
        int ShowPluginSettings()
        {
            try
            {
                // Create a settings dialog
                using (Form settingsForm = new Form())
                {
                    settingsForm.Text = "CE MCP Plugin Settings";
                    settingsForm.Size = new System.Drawing.Size(500, 400);
                    settingsForm.FormBorderStyle = FormBorderStyle.FixedDialog;
                    settingsForm.StartPosition = FormStartPosition.CenterParent;
                    settingsForm.MaximizeBox = false;
                    settingsForm.MinimizeBox = false;
                    
                    // Create a table layout panel
                    TableLayoutPanel panel = new TableLayoutPanel();
                    panel.Dock = DockStyle.Fill;
                    panel.ColumnCount = 2;
                    panel.RowCount = 7;
                    panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));
                    panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70));
                    for (int i = 0; i < panel.RowCount; i++)
                    {
                        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                    }
                    panel.Padding = new Padding(10, 10, 10, 10);
                    panel.Margin = new Padding(5);
                    
                    // Port setting
                    Label portLabel = new Label();
                    portLabel.Text = "Port:";
                    portLabel.Dock = DockStyle.Fill;
                    portLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
                    panel.Controls.Add(portLabel, 0, 0);
                    
                    NumericUpDown portUpDown = new NumericUpDown();
                    portUpDown.Value = config.Port;
                    portUpDown.Minimum = 1;
                    portUpDown.Maximum = 65535;
                    portUpDown.Dock = DockStyle.Fill;
                    panel.Controls.Add(portUpDown, 1, 0);
                    
                    // Log level setting
                    Label logLevelLabel = new Label();
                    logLevelLabel.Text = "Log Level:";
                    logLevelLabel.Dock = DockStyle.Fill;
                    logLevelLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
                    panel.Controls.Add(logLevelLabel, 0, 1);
                    
                    ComboBox logLevelComboBox = new ComboBox();
                    logLevelComboBox.Items.AddRange(new string[] { "Info", "Warning", "Error", "Debug" });
                    logLevelComboBox.SelectedItem = config.LogLevel;
                    logLevelComboBox.Dock = DockStyle.Fill;
                    panel.Controls.Add(logLevelComboBox, 1, 1);
                    
                    // Enable HTTPS setting
                    Label httpsLabel = new Label();
                    httpsLabel.Text = "Enable HTTPS:";
                    httpsLabel.Dock = DockStyle.Fill;
                    httpsLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
                    panel.Controls.Add(httpsLabel, 0, 2);
                    
                    CheckBox httpsCheckBox = new CheckBox();
                    httpsCheckBox.Checked = config.EnableHttps;
                    httpsCheckBox.Dock = DockStyle.Fill;
                    panel.Controls.Add(httpsCheckBox, 1, 2);
                    
                    // Enable Authentication setting
                    Label authLabel = new Label();
                    authLabel.Text = "Enable Authentication:";
                    authLabel.Dock = DockStyle.Fill;
                    authLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
                    panel.Controls.Add(authLabel, 0, 3);
                    
                    CheckBox authCheckBox = new CheckBox();
                    authCheckBox.Checked = config.EnableAuthentication;
                    authCheckBox.Dock = DockStyle.Fill;
                    panel.Controls.Add(authCheckBox, 1, 3);
                    
                    // API Token setting
                    Label tokenLabel = new Label();
                    tokenLabel.Text = "API Token:";
                    tokenLabel.Dock = DockStyle.Fill;
                    tokenLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
                    panel.Controls.Add(tokenLabel, 0, 4);
                    
                    TextBox tokenTextBox = new TextBox();
                    tokenTextBox.Text = config.ApiToken;
                    tokenTextBox.UseSystemPasswordChar = true;
                    tokenTextBox.Dock = DockStyle.Fill;
                    panel.Controls.Add(tokenTextBox, 1, 4);
                    
                    // Button container
                    Panel buttonPanel = new Panel();
                    buttonPanel.Dock = DockStyle.Fill;
                    buttonPanel.AutoSize = true;
                    
                    // OK button
                    Button okButton = new Button();
                    okButton.Text = "OK";
                    okButton.DialogResult = DialogResult.OK;
                    okButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
                    okButton.Location = new System.Drawing.Point(buttonPanel.Width - 180, 10);
                    buttonPanel.Controls.Add(okButton);
                    
                    // Cancel button
                    Button cancelButton = new Button();
                    cancelButton.Text = "Cancel";
                    cancelButton.DialogResult = DialogResult.Cancel;
                    cancelButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
                    cancelButton.Location = new System.Drawing.Point(buttonPanel.Width - 90, 10);
                    buttonPanel.Controls.Add(cancelButton);
                    
                    panel.Controls.Add(new Label(), 0, 5);
                    panel.Controls.Add(buttonPanel, 0, 6);
                    panel.SetColumnSpan(buttonPanel, 2);
                    
                    settingsForm.Controls.Add(panel);
                    settingsForm.AcceptButton = okButton;
                    settingsForm.CancelButton = cancelButton;
                    
                    // Show dialog
                    DialogResult result = settingsForm.ShowDialog();
                    
                    if (result == DialogResult.OK)
                    {
                        // Update configuration
                        config.Port = (int)portUpDown.Value;
                        config.LogLevel = logLevelComboBox.SelectedItem.ToString();
                        config.EnableHttps = httpsCheckBox.Checked;
                        config.EnableAuthentication = authCheckBox.Checked;
                        config.ApiToken = tokenTextBox.Text;
                        
                        // Save configuration
                        config.Save();
                        Log("Configuration saved successfully", LogLevel.Info);
                        sdk.lua.DoString("print('Configuration saved successfully')");
                    }
                }
            }
            catch (Exception ex)
            {
                string errorMsg = "Error showing plugin settings: " + ex.Message;
                Log(errorMsg, LogLevel.Error);
                sdk.lua.DoString($"print('Error: {errorMsg}')");
            }
            
            return 0;
        }
        
        void RunMCPServer(CancellationToken token)
        {
            try
            {
                Log("Running MCP server...");
                
                // Check if Python is available
                if (!IsPythonAvailable())
                {
                    string errorMsg = "Python is not available. Please install Python 3.11 or later.";
                    Log(errorMsg, LogLevel.Error);
                    sdk.lua.DoString($"print('Error: {errorMsg}')");
                    return;
                }

                // Check if fastmcp is installed, if not, install it
                if (!IsFastMCPInstalled())
                {
                    if (!InstallFastMCP())
                    {
                        string errorMsg = "Failed to install fastmcp library. Please install it manually with 'pip install fastmcp'.";
                        Log(errorMsg, LogLevel.Error);
                        sdk.lua.DoString($"print('Error: {errorMsg}')");
                        return;
                    }
                }

                // Create a unique temporary file name
                string scriptPath = Path.Combine(Path.GetTempPath(), $"ce_mcp_server_{Guid.NewGuid().ToString()}.py");
                tempFiles.Add(scriptPath);

                // Create a Python script for the MCP server
                string pythonScript = $@"from fastmcp import FastMCP
from mcp.types import Tool
import json
import socket
import requests
import time
import random

# Plugin configuration
CONFIG = {{
    'port': {config.Port},
    'enable_https': {config.EnableHttps},
    'enable_authentication': {config.EnableAuthentication},
    'api_token': '{config.ApiToken}',
    'local_server_url': 'http://localhost:' + str({config.Port} + 1)
}}

# CE Client class for communicating with CE via local HTTP server
class CE_Client:
    def __init__(self, base_url):
        self.base_url = base_url
        self.max_retries = 3  # Maximum number of retries
        self.retry_delay = 1  # Initial retry delay in seconds
        
    def call(self, action, params=None):
        """Call a CE action via the local HTTP server with retry mechanism"""
        data = {{'action': action}}
        if params:
            data.update(params)
        
        headers = {{
            'Content-Type': 'application/json'
        }}
        
        retry_count = 0
        while retry_count <= self.max_retries:
            try:
                response = requests.post(self.base_url, json=data, headers=headers, timeout=30)
                response.raise_for_status()
                return response.json()
            except Exception as e:
                retry_count += 1
                if retry_count > self.max_retries:
                    return {{
                        'success': False,
                        'error': str(e),
                        'retries': retry_count - 1
                    }}
                # Exponential backoff with jitter
                delay = self.retry_delay * (2 ** (retry_count - 1)) + (random.random() * 0.5)
                time.sleep(delay)
                continue

# Create CE client instance
ce_client = CE_Client(CONFIG['local_server_url'])

# Create MCP server instance
mcp_server = FastMCP()

# Configure MCP server if authentication is enabled
if CONFIG['enable_authentication'] and CONFIG['api_token']:
    # Set up authentication middleware
    def auth_middleware(request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return {'error': 'Authorization header required'}, 401
        
        token = auth_header.replace('Bearer ', '')
        if token != CONFIG['api_token']:
            return {'error': 'Invalid token'}, 403
        return None  # No error, continue processing
    
    mcp_server.add_middleware(auth_middleware)

# Define CE tools that AI can use
ce_tools = [
    # Process Management Module
    Tool(
        name='ce_get_process_list',
        description='Get a list of running processes',
        parameters={
            'type': 'object',
            'properties': {}
        }
    ),
    Tool(
        name='ce_attach_to_process',
        description='Attach to a specified process',
        parameters={
            'type': 'object',
            'properties': {
                'process_id': {
                    'type': 'integer',
                    'description': 'Process ID'
                }
            },
            'required': ['process_id']
        }
    ),
    Tool(
        name='ce_detach_from_process',
        description='Detach from current process',
        parameters={
            'type': 'object',
            'properties': {}
        }
    ),
    
    # Memory Operation Module
    Tool(
        name='ce_read_memory',
        description='Read memory from a process',
        parameters={
            'type': 'object',
            'properties': {
                'process_id': {
                    'type': 'integer',
                    'description': 'Process ID (optional, default current attached process)'
                },
                'address': {
                    'type': 'string',
                    'description': 'Memory address (hex format)'
                },
                'size': {
                    'type': 'integer',
                    'description': 'Number of bytes to read'
                },
                'data_type': {
                    'type': 'string',
                    'description': 'Data type (optional, default raw)',
                    'enum': ['raw', 'byte', 'word', 'dword', 'qword', 'float', 'double', 'string']
                }
            },
            'required': ['address', 'size']
        }
    ),
    Tool(
        name='ce_write_memory',
        description='Write memory to a process',
        parameters={
            'type': 'object',
            'properties': {
                'process_id': {
                    'type': 'integer',
                    'description': 'Process ID (optional, default current attached process)'
                },
                'address': {
                    'type': 'string',
                    'description': 'Memory address (hex format)'
                },
                'value': {
                    'type': 'string',
                    'description': 'Value to write'
                },
                'data_type': {
                    'type': 'string',
                    'description': 'Data type (optional, default raw)',
                    'enum': ['raw', 'byte', 'word', 'dword', 'qword', 'float', 'double', 'string']
                }
            },
            'required': ['address', 'value']
        }
    ),
    Tool(
        name='ce_scan_memory',
        description='Scan process memory for a specific value',
        parameters={
            'type': 'object',
            'properties': {
                'process_id': {
                    'type': 'integer',
                    'description': 'Process ID (optional, default current attached process)'
                },
                'value': {
                    'type': 'string',
                    'description': 'Value to scan for'
                },
                'data_type': {
                    'type': 'string',
                    'description': 'Data type',
                    'enum': ['byte', 'word', 'dword', 'qword', 'float', 'double', 'string', 'array']
                },
                'scan_type': {
                    'type': 'string',
                    'description': 'Scan type',
                    'enum': ['exact_value', 'unknown_initial_value', 'increased_value', 'decreased_value', 'value_between']
                }
            },
            'required': ['value', 'data_type', 'scan_type']
        }
    ),
    Tool(
        name='ce_freeze_memory',
        description='Freeze a memory address to a specific value',
        parameters={
            'type': 'object',
            'properties': {
                'address': {
                    'type': 'string',
                    'description': 'Memory address (hex format)'
                },
                'value': {
                    'type': 'string',
                    'description': 'Value to freeze'
                },
                'data_type': {
                    'type': 'string',
                    'description': 'Data type',
                    'enum': ['byte', 'word', 'dword', 'qword', 'float', 'double']
                }
            },
            'required': ['address', 'value', 'data_type']
        }
    ),
    Tool(
        name='ce_unfreeze_memory',
        description='Unfreeze a memory address',
        parameters={
            'type': 'object',
            'properties': {
                'freeze_id': {
                    'type': 'integer',
                    'description': 'Freeze ID'
                }
            },
            'required': ['freeze_id']
        }
    ),
    
    # Pointer Operation Module
    Tool(
        name='ce_calculate_pointer_address',
        description='Calculate pointer address from base address and offsets',
        parameters={
            'type': 'object',
            'properties': {
                'base_address': {
                    'type': 'string',
                    'description': 'Base address (hex format)'
                },
                'offsets': {
                    'type': 'array',
                    'description': 'List of offsets',
                    'items': {
                        'type': 'integer'
                    }
                }
            },
            'required': ['base_address', 'offsets']
        }
    ),
    Tool(
        name='ce_find_pointers',
        description='Find pointers to a specific address',
        parameters={
            'type': 'object',
            'properties': {
                'target_address': {
                    'type': 'string',
                    'description': 'Target address (hex format)'
                },
                'max_level': {
                    'type': 'integer',
                    'description': 'Maximum pointer level',
                    'default': 5
                },
                'max_offsets': {
                    'type': 'integer',
                    'description': 'Maximum number of offsets per pointer',
                    'default': 1000
                }
            },
            'required': ['target_address']
        }
    ),
    
    # Disassembly and Debug Module
    Tool(
        name='ce_disassemble',
        description='Disassemble code at specified address',
        parameters={
            'type': 'object',
            'properties': {
                'address': {
                    'type': 'string',
                    'description': 'Start address (hex format)'
                },
                'instruction_count': {
                    'type': 'integer',
                    'description': 'Number of instructions to disassemble',
                    'default': 10
                }
            },
            'required': ['address']
        }
    ),
    Tool(
        name='ce_set_breakpoint',
        description='Set a breakpoint at specified address',
        parameters={
            'type': 'object',
            'properties': {
                'address': {
                    'type': 'string',
                    'description': 'Address to set breakpoint (hex format)'
                },
                'breakpoint_type': {
                    'type': 'string',
                    'description': 'Breakpoint type',
                    'enum': ['execute', 'read', 'write', 'access']
                }
            },
            'required': ['address', 'breakpoint_type']
        }
    ),
    Tool(
        name='ce_remove_breakpoint',
        description='Remove a breakpoint at specified address',
        parameters={
            'type': 'object',
            'properties': {
                'address': {
                    'type': 'string',
                    'description': 'Address to remove breakpoint (hex format)'
                }
            },
            'required': ['address']
        }
    ),
    
    # Lua Script Support Module
    Tool(
        name='ce_execute_lua',
        description='Execute Lua script in CE',
        parameters={
            'type': 'object',
            'properties': {
                'script': {
                    'type': 'string',
                    'description': 'Lua script to execute'
                }
            },
            'required': ['script']
        }
    ),
    
    # Module and Section Management
    Tool(
        name='ce_get_modules',
        description='Get a list of modules in the current process',
        parameters={
            'type': 'object',
            'properties': {
                'process_id': {
                    'type': 'integer',
                    'description': 'Process ID (optional, default current attached process)'
                }
            }
        }
    ),
    Tool(
        name='ce_get_module_sections',
        description='Get sections of a specific module',
        parameters={
            'type': 'object',
            'properties': {
                'module_name': {
                    'type': 'string',
                    'description': 'Module name (e.g., kernel32.dll)'
                }
            },
            'required': ['module_name']
        }
    ),
    
    # Cheat Table Management
    Tool(
        name='ce_save_cheat_table',
        description='Save current cheat table to a file',
        parameters={
            'type': 'object',
            'properties': {
                'file_path': {
                    'type': 'string',
                    'description': 'Path to save the cheat table'
                }
            },
            'required': ['file_path']
        }
    ),
    Tool(
        name='ce_load_cheat_table',
        description='Load a cheat table from a file',
        parameters={
            'type': 'object',
            'properties': {
                'file_path': {
                    'type': 'string',
                    'description': 'Path to the cheat table file'
                }
            },
            'required': ['file_path']
        }
    ),
    # Advanced Memory and Process Management
    Tool(
        name='ce_allocate_memory',
        description='Allocate memory in the current process',
        parameters={
            'type': 'object',
            'properties': {
                'size': {
                    'type': 'integer',
                    'description': 'Number of bytes to allocate'
                },
                'protection': {
                    'type': 'string',
                    'description': 'Memory protection type (default: PAGE_EXECUTE_READWRITE)',
                    'enum': ['PAGE_NOACCESS', 'PAGE_READONLY', 'PAGE_READWRITE', 'PAGE_EXECUTE', 'PAGE_EXECUTE_READ', 'PAGE_EXECUTE_READWRITE']
                }
            },
            'required': ['size']
        }
    ),
    Tool(
        name='ce_deallocate_memory',
        description='Deallocate memory in the current process',
        parameters={
            'type': 'object',
            'properties': {
                'address': {
                    'type': 'string',
                    'description': 'Memory address to deallocate (hex format)'
                }
            },
            'required': ['address']
        }
    ),
    Tool(
        name='ce_inject_code',
        description='Inject code into a specific memory address',
        parameters={
            'type': 'object',
            'properties': {
                'address': {
                    'type': 'string',
                    'description': 'Memory address to inject code into (hex format)'
                },
                'code': {
                    'type': 'string',
                    'description': 'Hex bytes to inject'
                }
            },
            'required': ['address', 'code']
        }
    ),
    # Thread Management
    Tool(
        name='ce_get_threads',
        description='Get a list of threads in the current process',
        parameters={
            'type': 'object',
            'properties': {}
        }
    ),
    Tool(
        name='ce_suspend_thread',
        description='Suspend a thread',
        parameters={
            'type': 'object',
            'properties': {
                'thread_id': {
                    'type': 'integer',
                    'description': 'Thread ID to suspend'
                }
            },
            'required': ['thread_id']
        }
    ),
    Tool(
        name='ce_resume_thread',
        description='Resume a suspended thread',
        parameters={
            'type': 'object',
            'properties': {
                'thread_id': {
                    'type': 'integer',
                    'description': 'Thread ID to resume'
                }
            },
            'required': ['thread_id']
        }
    ),
    # Handle Management
    Tool(
        name='ce_get_handles',
        description='Get a list of handles in the current process',
        parameters={
            'type': 'object',
            'properties': {}
        }
    ),
    # Symbol and Expression Evaluation
    Tool(
        name='ce_get_symbol_address',
        description='Get the address of a symbol in a module',
        parameters={
            'type': 'object',
            'properties': {
                'module_name': {
                    'type': 'string',
                    'description': 'Module name (e.g., kernel32.dll)'
                },
                'symbol_name': {
                    'type': 'string',
                    'description': 'Symbol name'
                }
            },
            'required': ['module_name', 'symbol_name']
        }
    ),
    Tool(
        name='ce_evaluate_expression',
        description='Evaluate an expression in Cheat Engine context',
        parameters={
            'type': 'object',
            'properties': {
                'expression': {
                    'type': 'string',
                    'description': 'Expression to evaluate'
                }
            },
            'required': ['expression']
        }
    ),
    # Health Check
    Tool(
        name='ce_health_check',
        description='Perform a health check on the plugin and CE integration',
        parameters={
            'type': 'object',
            'properties': {}
        }
    )
]

# Add tools to the MCP server
for tool in ce_tools:
    mcp_server.add_tool(tool)

# Define tool handlers
@mcp_server.handle_tool('ce_get_process_list')
def handle_get_process_list(params):
    return ce_client.call('get_process_list')

@mcp_server.handle_tool('ce_attach_to_process')
def handle_attach_to_process(params):
    return ce_client.call('attach_to_process', params)

@mcp_server.handle_tool('ce_detach_from_process')
def handle_detach_from_process(params):
    return ce_client.call('detach_from_process')

@mcp_server.handle_tool('ce_read_memory')
def handle_read_memory(params):
    return ce_client.call('read_memory', params)

@mcp_server.handle_tool('ce_write_memory')
def handle_write_memory(params):
    return ce_client.call('write_memory', params)

@mcp_server.handle_tool('ce_scan_memory')
def handle_scan_memory(params):
    return ce_client.call('scan_memory', params)

@mcp_server.handle_tool('ce_freeze_memory')
def handle_freeze_memory(params):
    return ce_client.call('freeze_memory', params)

@mcp_server.handle_tool('ce_unfreeze_memory')
def handle_unfreeze_memory(params):
    return ce_client.call('unfreeze_memory', params)

@mcp_server.handle_tool('ce_calculate_pointer_address')
def handle_calculate_pointer_address(params):
    return ce_client.call('calculate_pointer_address', params)

@mcp_server.handle_tool('ce_find_pointers')
def handle_find_pointers(params):
    return ce_client.call('find_pointers', params)

@mcp_server.handle_tool('ce_disassemble')
def handle_disassemble(params):
    return ce_client.call('disassemble', params)

@mcp_server.handle_tool('ce_set_breakpoint')
def handle_set_breakpoint(params):
    return ce_client.call('set_breakpoint', params)

@mcp_server.handle_tool('ce_remove_breakpoint')
def handle_remove_breakpoint(params):
    return ce_client.call('remove_breakpoint', params)

@mcp_server.handle_tool('ce_execute_lua')
def handle_execute_lua(params):
    return ce_client.call('execute_lua', params)

@mcp_server.handle_tool('ce_get_modules')
def handle_get_modules(params):
    return ce_client.call('get_modules', params)

@mcp_server.handle_tool('ce_get_module_sections')
def handle_get_module_sections(params):
    return ce_client.call('get_module_sections', params)

@mcp_server.handle_tool('ce_save_cheat_table')
def handle_save_cheat_table(params):
    return ce_client.call('save_cheat_table', params)

@mcp_server.handle_tool('ce_load_cheat_table')
def handle_load_cheat_table(params):
    return ce_client.call('load_cheat_table', params)

# Advanced CE Features
def handle_advanced_ce_feature(name, params):
    """Generic handler for advanced CE features"""
    return ce_client.call(name.replace('ce_', ''), params)

@mcp_server.handle_tool('ce_allocate_memory')
def handle_allocate_memory(params):
    return handle_advanced_ce_feature('ce_allocate_memory', params)

@mcp_server.handle_tool('ce_deallocate_memory')
def handle_deallocate_memory(params):
    return handle_advanced_ce_feature('ce_deallocate_memory', params)

@mcp_server.handle_tool('ce_inject_code')
def handle_inject_code(params):
    return handle_advanced_ce_feature('ce_inject_code', params)

@mcp_server.handle_tool('ce_get_threads')
def handle_get_threads(params):
    return handle_advanced_ce_feature('ce_get_threads', params)

@mcp_server.handle_tool('ce_suspend_thread')
def handle_suspend_thread(params):
    return handle_advanced_ce_feature('ce_suspend_thread', params)

@mcp_server.handle_tool('ce_resume_thread')
def handle_resume_thread(params):
    return handle_advanced_ce_feature('ce_resume_thread', params)

@mcp_server.handle_tool('ce_get_handles')
def handle_get_handles(params):
    return handle_advanced_ce_feature('ce_get_handles', params)

@mcp_server.handle_tool('ce_get_symbol_address')
def handle_get_symbol_address(params):
    return handle_advanced_ce_feature('ce_get_symbol_address', params)

@mcp_server.handle_tool('ce_evaluate_expression')
def handle_evaluate_expression(params):
    return handle_advanced_ce_feature('ce_evaluate_expression', params)

@mcp_server.handle_tool('ce_health_check')
def handle_health_check(params):
    return handle_advanced_ce_feature('ce_health_check', params)

# Start the MCP server
if CONFIG['enable_https']:
    # HTTPS configuration
    print(f'MCP Server is running on https://localhost:{CONFIG["port"]}')
    mcp_server.run(host='0.0.0.0', port=CONFIG['port'], ssl_context=(CONFIG.get('certificate_path', None), CONFIG.get('certificate_key', None)))
else:
    # HTTP configuration
    print(f'MCP Server is running on http://localhost:{CONFIG["port"]}')
    mcp_server.run(host='0.0.0.0', port=CONFIG['port'])}}}";

                // Write the script to a temporary file
                File.WriteAllText(scriptPath, pythonScript);
                Log("Created temporary Python script: " + scriptPath);

                // Create process to run the Python script
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "python";
                startInfo.Arguments = scriptPath;
                startInfo.UseShellExecute = false;
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;
                startInfo.CreateNoWindow = true;

                Process process = new Process();
                process.StartInfo = startInfo;

                // Handle output
                process.OutputDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        string logMsg = "MCP Server Output: " + e.Data;
                        Log(logMsg, LogLevel.Info);
                        sdk.lua.DoString($"print('{logMsg.Replace("'", "''")}')");
                    }
                };

                process.ErrorDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        string errorMsg = "MCP Server Error: " + e.Data;
                        Log(errorMsg, LogLevel.Error);
                        sdk.lua.DoString($"print('{errorMsg.Replace("'", "''")}')");
                    }
                };

                // Start the process
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                Log("MCP server process started");

                // Keep track of the process
                mcpServerProcess = process;

                // Wait for the process to exit or cancellation request
                while (!process.HasExited && !token.IsCancellationRequested)
                {
                    // Check cancellation token with a timeout
                    if (token.WaitHandle.WaitOne(1000))
                    {
                        // Cancellation requested
                        Log("MCP server thread received cancellation request");
                        break;
                    }
                }

                // If cancellation was requested and process is still running, kill it
                if (token.IsCancellationRequested && !process.HasExited)
                {
                    try
                    {
                        Log("Killing MCP server process due to cancellation");
                        process.Kill();
                        process.WaitForExit(5000);
                    }
                    catch (Exception ex)
                    {
                        Log("Error killing MCP server process: " + ex.Message, LogLevel.Error);
                    }
                }

                // Get exit code if process exited
                int exitCode = process.HasExited ? process.ExitCode : -1;
                Log($"MCP server process exited with code: {exitCode}");

                // Clean up
                if (tempFiles.Contains(scriptPath))
                {
                    tempFiles.Remove(scriptPath);
                    if (File.Exists(scriptPath))
                    {
                        try
                        {
                            File.Delete(scriptPath);
                            Log("Deleted temporary Python script: " + scriptPath);
                        }
                        catch (Exception ex)
                        {
                            Log("Error deleting temporary script: " + ex.Message, LogLevel.Warning);
                        }
                    }
                }

                // Clean up process resources
                process.Dispose();
                mcpServerProcess = null;
            }
            catch (OperationCanceledException)
            {
                Log("MCP server thread was canceled");
            }
            catch (Exception ex)
            {
                string errorMsg = "MCP Server Error: " + ex.Message;
                Log(errorMsg, LogLevel.Error);
                sdk.lua.DoString($"print('{errorMsg.Replace("'", "''")}')");
            }
        }
    }
}