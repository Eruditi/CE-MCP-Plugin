using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Newtonsoft.Json;

namespace CEPluginLibrary
{
    /// <summary>
    /// 插件配置类
    /// </summary>
    public class Configuration
    {
        /// <summary>
        /// 默认配置
        /// </summary>
        public static Configuration Default
        {
            get
            {
                return new Configuration
                {
                    Port = 18888,
                    LogLevel = "Info",
                    EnableHttps = false,
                    EnableAuthentication = false,
                    ApiToken = string.Empty,
                    CertificatePath = string.Empty,
                    CertificatePassword = string.Empty
                };
            }
        }

        /// <summary>
        /// MCP服务器端口
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// 日志级别
        /// </summary>
        public string LogLevel { get; set; }

        /// <summary>
        /// 是否启用HTTPS
        /// </summary>
        public bool EnableHttps { get; set; }

        /// <summary>
        /// 是否启用认证
        /// </summary>
        public bool EnableAuthentication { get; set; }

        /// <summary>
        /// API令牌
        /// </summary>
        public string ApiToken { get; set; }

        /// <summary>
        /// 证书路径
        /// </summary>
        public string CertificatePath { get; set; }

        /// <summary>
        /// 证书密码
        /// </summary>
        public string CertificatePassword { get; set; }

        /// <summary>
        /// 配置文件路径
        /// </summary>
        public static string ConfigFilePath
        {
            get
            {
                string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string cePluginPath = Path.Combine(appDataPath, "Cheat Engine", "Plugins", "CEMCPPlugin");
                Directory.CreateDirectory(cePluginPath);
                return Path.Combine(cePluginPath, "config.json");
            }
        }

        /// <summary>
        /// 加载配置
        /// </summary>
        /// <returns>配置对象</returns>
        public static Configuration Load()
        {
            try
            {
                string configPath = ConfigFilePath;
                if (File.Exists(configPath))
                {
                    string json = File.ReadAllText(configPath);
                    Configuration config = JsonConvert.DeserializeObject<Configuration>(json);
                    return config;
                }
            }
            catch (Exception ex)
            {
                // 忽略配置加载错误，使用默认配置
            }
            return Default;
        }

        /// <summary>
        /// 保存配置
        /// </summary>
        public void Save()
        {
            try
            {
                string configPath = ConfigFilePath;
                string json = JsonConvert.SerializeObject(this, Formatting.Indented);
                File.WriteAllText(configPath, json);
            }
            catch (Exception ex)
            {
                // 忽略配置保存错误
            }
        }
    }
}