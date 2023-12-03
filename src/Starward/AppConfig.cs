﻿using Dapper;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Starward.Core;
using Starward.Core.Gacha.Genshin;
using Starward.Core.Gacha.StarRail;
using Starward.Core.GameRecord;
using Starward.Core.Launcher;
using Starward.Core.Metadata;
using Starward.Core.SelfQuery;
using Starward.Services;
using Starward.Services.Gacha;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Starward;

internal static class AppConfig
{


    public static string? AppVersion { get; private set; }


    public static bool IsPortable { get; private set; }


    public static IConfigurationRoot Configuration { get; private set; }


    public static string LogFile { get; private set; }


    public static readonly JsonSerializerOptions JsonSerializerOptions = new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };


    private static IServiceProvider _serviceProvider;


    static AppConfig()
    {
        Initialize();
    }




    #region UriSource


    public static Uri EmojiPaimon = new Uri("ms-appx:///Assets/Image/UI_EmotionIcon5.png");

    public static Uri EmojiPom = new Uri("ms-appx:///Assets/Image/20008.png");

    public static Uri EmojiAI = new Uri("ms-appx:///Assets/Image/bdfd19c3bdad27a395890755bb60b162.png");


    #endregion



    #region Ini Config


    private static int windowSizeMode;
    public static int WindowSizeMode
    {
        get => windowSizeMode;
        set
        {
            windowSizeMode = value;
            SaveConfiguration();
        }
    }

    private static string? language;
    public static string? Language
    {
        get => language;
        set
        {
            language = value;
            SaveConfiguration();
        }
    }

    private static string userDataFolder;
    public static string UserDataFolder
    {
        get => userDataFolder;
        set
        {
            userDataFolder = value;
            SaveConfiguration();
        }
    }


    public static bool DisableNavigationShortcut { get; set; }

    public static bool DisableGameNoticeRedHot { get; set; }

    public static bool DisableGameAccountSwitcher { get; set; }

    public static bool EnableSystemAccentColor { get; set; }

    public static bool EnableNavigationViewLeftCompact { get; set; } = true;



    private static void Initialize()
    {
        try
        {
            AppVersion = typeof(AppConfig).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            var webviewFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Starward\webview");
            Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER", webviewFolder, EnvironmentVariableTarget.Process);

            string? baseDir = Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd('\\'));
            string exe = Path.Join(baseDir, "Starward.exe");
            if (File.Exists(exe))
            {
                IsPortable = true;
            }
            else
            {
                baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Starward");
                Directory.CreateDirectory(baseDir);
            }
            string? iniPath = Path.Join(baseDir, "config.ini");
            var builder = new ConfigurationBuilder().AddCommandLine(Environment.GetCommandLineArgs());
            if (File.Exists(iniPath))
            {
                builder.AddIniFile(iniPath);
            }
            Configuration = builder.Build();

            windowSizeMode = Configuration.GetValue<int>(nameof(WindowSizeMode));
            language = Configuration.GetValue<string>(nameof(Language));
            DisableNavigationShortcut = Configuration.GetValue<bool>(nameof(DisableNavigationShortcut));
            DisableGameNoticeRedHot = Configuration.GetValue<bool>(nameof(DisableGameNoticeRedHot));
            DisableGameAccountSwitcher = Configuration.GetValue<bool>(nameof(DisableGameAccountSwitcher));
            EnableSystemAccentColor = Configuration.GetValue<bool>(nameof(EnableSystemAccentColor));
            EnableNavigationViewLeftCompact = Configuration.GetValue<bool>(nameof(EnableNavigationViewLeftCompact), true);
            string? dir = Configuration.GetValue<string>(nameof(UserDataFolder));
            if (!string.IsNullOrWhiteSpace(dir))
            {
                string folder;
                if (Path.IsPathFullyQualified(dir))
                {
                    folder = dir;
                }
                else
                {
                    folder = Path.Join(baseDir, dir);
                }
                if (Directory.Exists(folder))
                {
                    userDataFolder = Path.GetFullPath(folder);
                }
            }
        }
        catch
        {
            Configuration ??= new ConfigurationBuilder().AddCommandLine(Environment.GetCommandLineArgs()).Build();
        }
    }



    private static void SaveConfiguration()
    {
        try
        {
            string dataFolder = UserDataFolder;
            string baseDir;
            if (IsPortable)
            {
                baseDir = Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd('\\'))!;
            }
            else
            {
                baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Starward");
            }
            if (dataFolder?.StartsWith(baseDir) ?? false)
            {
                dataFolder = Path.GetRelativePath(baseDir, dataFolder);
            }
            File.WriteAllText(Path.Combine(baseDir, "config.ini"), $"""
                {nameof(WindowSizeMode)}={WindowSizeMode}
                {nameof(Language)}={Language}
                {nameof(UserDataFolder)}={dataFolder}
                {nameof(DisableNavigationShortcut)}={DisableNavigationShortcut}
                {nameof(DisableGameNoticeRedHot)}={DisableGameNoticeRedHot}
                {nameof(DisableGameAccountSwitcher)}={DisableGameAccountSwitcher}
                {nameof(EnableSystemAccentColor)}={EnableSystemAccentColor}
                {nameof(EnableNavigationViewLeftCompact)}={EnableNavigationViewLeftCompact}
                """);
        }
        catch { }
    }




    #endregion




    #region Service Provider


    public static void ResetServiceProvider()
    {
        cache.Clear();
        _serviceProvider = null!;
        DatabaseService = null!;
    }


    private static void BuildServiceProvider()
    {
        if (_serviceProvider == null)
        {
            var logFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Starward\log");
            Directory.CreateDirectory(logFolder);
            LogFile = Path.Combine(logFolder, $"Starward_{DateTime.Now:yyMMdd_HHmmss}.log");
            Log.Logger = new LoggerConfiguration().WriteTo.File(path: LogFile, outputTemplate: "[{Timestamp:HH:mm:ss.fff}] [{Level:u4}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}")
                                                  .Enrich.FromLogContext()
                                                  .CreateLogger();
            Log.Information($"Welcome to Starward v{AppVersion}\r\nSystem: {Environment.OSVersion}\r\nCommand Line: {Environment.CommandLine}");

            var sc = new ServiceCollection();
            sc.AddLogging(c => c.AddSimpleConsole(c => c.TimestampFormat = "HH:mm:ss.fff\r\n"));
            sc.AddLogging(c => c.AddSerilog(Log.Logger));
            sc.AddTransient(_ =>
            {
                var client = new HttpClient(new HttpClientHandler { AutomaticDecompression = DecompressionMethods.All }) { DefaultRequestVersion = HttpVersion.Version20 };
                client.DefaultRequestHeaders.Add("User-Agent", $"Starward/{AppVersion}");
                return client;
            });

            sc.AddSingleton<GenshinGachaClient>();
            sc.AddSingleton<StarRailGachaClient>();
            sc.AddSingleton<HyperionClient>();
            sc.AddSingleton<HyperionClient>();
            sc.AddSingleton<HoyolabClient>();
            sc.AddSingleton<LauncherClient>();
            sc.AddSingleton<SelfQueryClient>();
            sc.AddSingleton(p => new MetadataClient(ApiCDNIndex, p.GetService<HttpClient>()));

            sc.AddSingleton<DatabaseService>();
            sc.AddSingleton<GameService>();
            sc.AddSingleton<UpdateService>();
            sc.AddSingleton<LauncherService>();
            sc.AddSingleton<GenshinGachaService>();
            sc.AddSingleton<StarRailGachaService>();
            sc.AddSingleton<PlayTimeService>();
            sc.AddSingleton<DownloadGameService>();
            sc.AddSingleton<GameSettingService>();
            sc.AddSingleton<GameRecordService>();
            sc.AddSingleton<WelcomeService>();
            sc.AddSingleton<SystemTrayService>();
            sc.AddSingleton<SelfQueryService>();

            _serviceProvider = sc.BuildServiceProvider();
            if (!string.IsNullOrWhiteSpace(UserDataFolder))
            {
                _serviceProvider.GetService<DatabaseService>()!.SetDatabase(UserDataFolder);
            }
        }
    }


    public static T GetService<T>()
    {
        BuildServiceProvider();
        return _serviceProvider.GetService<T>()!;
    }


    public static ILogger<T> GetLogger<T>()
    {
        BuildServiceProvider();
        return _serviceProvider.GetService<ILogger<T>>()!;
    }




    #endregion





    #region Static Setting



    public static int ApiCDNIndex
    {
        get => GetValue<int>();
        set => SetValue(value);
    }


    public static bool EnablePreviewRelease
    {
        get => GetValue<bool>();
        set => SetValue(value);
    }


    public static string? IgnoreVersion
    {
        get => GetValue<string>();
        set => SetValue(value);
    }


    public static bool EnableBannerAndPost
    {
        get => GetValue(true);
        set => SetValue(value);
    }


    public static bool IgnoreRunningGame
    {
        get => GetValue<bool>();
        set => SetValue(value);
    }


    public static GameBiz SelectGameBiz
    {
        get => GetValue<GameBiz>();
        set => SetValue(value);
    }


    public static bool ShowNoviceGacha
    {
        get => GetValue<bool>();
        set => SetValue(value);
    }


    public static string? GachaLanguage
    {
        get => GetValue<string>();
        set => SetValue(value);
    }


    public static string? AccentColor
    {
        get => GetValue<string>();
        set => SetValue(value);
    }


    public static int VideoBgVolume
    {
        get => Math.Clamp(GetValue(100), 0, 100);
        set => SetValue(value);
    }


    public static bool UseOneBg
    {
        get => GetValue<bool>();
        set => SetValue(value);
    }


    public static bool AcceptHoyolabToolboxAgreement
    {
        get => GetValue<bool>();
        set => SetValue(value);
    }


    public static bool HoyolabToolboxPaneOpen
    {
        get => GetValue(true);
        set => SetValue(value);
    }


    public static bool EnableSystemTrayIcon
    {
        get => GetValue<bool>();
        set => SetValue(value);
    }


    public static bool ExitWhenClosing
    {
        get => GetValue<bool>();
        set => SetValue(value);
    }


    #endregion





    #region Dynamic Setting


    public static string? GetBg(GameBiz biz)
    {
        return GetValue<string>(default, $"bg_{biz}");
    }

    public static void SetBg(GameBiz biz, string? value)
    {
        SetValue(value, $"bg_{biz}");
    }



    public static string? GetCustomBg(GameBiz biz)
    {
        return GetValue<string>(default, UseOneBg ? $"custom_bg_{GameBiz.All}" : $"custom_bg_{biz}");
    }

    public static void SetCustomBg(GameBiz biz, string? value)
    {
        SetValue(value, UseOneBg ? $"custom_bg_{GameBiz.All}" : $"custom_bg_{biz}");
    }



    public static bool GetEnableCustomBg(GameBiz biz)
    {
        return GetValue<bool>(default, UseOneBg ? $"enable_custom_bg_{GameBiz.All}" : $"enable_custom_bg_{biz}");
    }

    public static void SetEnableCustomBg(GameBiz biz, bool value)
    {
        SetValue(value, UseOneBg ? $"enable_custom_bg_{GameBiz.All}" : $"enable_custom_bg_{biz}");
    }



    public static string? GetGameInstallPath(GameBiz biz)
    {
        return GetValue<string>(default, $"install_path_{biz}");
    }

    public static void SetGameInstallPath(GameBiz biz, string? value)
    {
        SetValue(value, $"install_path_{biz}");
    }



    public static bool GetEnableThirdPartyTool(GameBiz biz)
    {
        return GetValue<bool>(default, $"enable_third_party_tool_{biz}");
    }

    public static void SetEnableThirdPartyTool(GameBiz biz, bool value)
    {
        SetValue(value, $"enable_third_party_tool_{biz}");
    }



    public static string? GetThirdPartyToolPath(GameBiz biz)
    {
        return GetValue<string>(default, $"third_party_tool_path_{biz}");
    }

    public static void SetThirdPartyToolPath(GameBiz biz, string? value)
    {
        SetValue(value, $"third_party_tool_path_{biz}");
    }



    public static string? GetStartArgument(GameBiz biz)
    {
        return GetValue<string>(default, $"start_argument_{biz}");
    }

    public static void SetStartArgument(GameBiz biz, string? value)
    {
        SetValue(value, $"start_argument_{biz}");
    }



    public static long GetLastUidInGachaLogPage(GameBiz biz)
    {
        return GetValue<long>(default, $"last_gacha_uid_{biz}");
    }

    public static void SetLastUidInGachaLogPage(GameBiz biz, long value)
    {
        SetValue(value, $"last_gacha_uid_{biz}");
    }


    public static GameBiz GetLastRegionOfGame(GameBiz game)
    {
        return GetValue<GameBiz>(default, $"last_region_of_{game}");
    }

    public static void SetLastRegionOfGame(GameBiz game, GameBiz value)
    {
        SetValue(value, $"last_region_of_{game}");
    }




    #endregion




    #region Setting Method



    private static DatabaseService DatabaseService;

    private static Dictionary<string, string?> cache;


    private static void InitializeSettingProvider()
    {
        try
        {
            DatabaseService ??= GetService<DatabaseService>();
            if (cache is null)
            {
                using var dapper = DatabaseService.CreateConnection();
                cache = dapper.Query<(string Key, string? Value)>("SELECT Key, Value FROM Setting;").ToDictionary(x => x.Key, x => x.Value);
            }
        }
        catch { }
    }



    private static T? GetValue<T>(T? defaultValue = default, [CallerMemberName] string? key = null)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return defaultValue;
        }
        if (string.IsNullOrWhiteSpace(UserDataFolder))
        {
            return defaultValue;
        }
        InitializeSettingProvider();
        try
        {
            if (cache.TryGetValue(key, out string? value))
            {
                return ConvertFromString(value, defaultValue);
            }
            using var dapper = DatabaseService.CreateConnection();
            value = dapper.QueryFirstOrDefault<string>("SELECT Value FROM Setting WHERE Key=@key LIMIT 1;", new { key });
            cache[key] = value;
            return ConvertFromString(value, defaultValue);
        }
        catch
        {
            return defaultValue;
        }
    }


    private static T? ConvertFromString<T>(string? value, T? defaultValue = default)
    {
        if (value is null)
        {
            return defaultValue;
        }
        var converter = TypeDescriptor.GetConverter(typeof(T));
        if (converter == null)
        {
            return defaultValue;
        }
        return (T?)converter.ConvertFromString(value);
    }


    private static void SetValue<T>(T? value, [CallerMemberName] string? key = null)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(UserDataFolder))
        {
            return;
        }
        InitializeSettingProvider();
        try
        {
            string? val = value?.ToString();
            if (cache.TryGetValue(key, out string? cacheValue) && cacheValue == val)
            {
                return;
            }
            cache[key] = val;
            using var dapper = DatabaseService.CreateConnection();
            dapper.Execute("INSERT OR REPLACE INTO Setting (Key, Value) VALUES (@key, @val);", new { key, val });
        }
        catch { }
    }



    public static void DeleteAllSettings()
    {
        try
        {
            using var dapper = DatabaseService.CreateConnection();
            dapper.Execute("DELETE FROM Setting WHERE TRUE;");
        }
        catch { }
    }


    #endregion


}
