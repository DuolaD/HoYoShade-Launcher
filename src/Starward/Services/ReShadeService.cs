using Microsoft.Extensions.Logging;
using Serilog.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Starward.Core;
using Vanara.PInvoke;

namespace Starward.Services
{
    internal class ReShadeService
    {
        private readonly ILogger<ReShadeService> _logger;
        private readonly GameService _gameService;

        private readonly string _currentPath;

        public ReShadeService(
            ILogger<ReShadeService> logger,
            GameService gameService)
        {
            _logger = logger;
            _gameService = gameService;

            var currentProcessPath = Process.GetCurrentProcess().MainModule.FileName;
            _currentPath = Path.GetDirectoryName(currentProcessPath);
        }

        /*
         reshade loader
        
         struct loading_data
         {
           WCHAR load_path[MAX_PATH] = L"";
           decltype(&GetLastError) GetLastError = nullptr;
           decltype(&LoadLibraryW) LoadLibraryW = nullptr;
           const WCHAR env_var_name[30] = L"RESHADE_DISABLE_LOADING_CHECK";
           const WCHAR env_var_value[2] = L"1";
           decltype(&SetEnvironmentVariableW) SetEnvironmentVariableW = nullptr;
         };

         static DWORD WINAPI loading_thread_func(loading_data *arg)
         {
           arg->SetEnvironmentVariableW(arg->env_var_name, arg->env_var_value);
           if (arg->LoadLibraryW(arg->load_path) == NULL)
           return arg->GetLastError();
           return ERROR_SUCCESS;
         }
        
         */

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        private struct LoadingData
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string LoadPath;
            public IntPtr GetLastError;
            public IntPtr LoadLibraryW;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 30)]
            public string EnvVarName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 2)]
            public string EnvVarValue;
            public IntPtr SetEnvironmentVariableW;
        }

        public void OnGameStart(Process gameProcess, GameBiz gameBiz)
        {
            var loaderStub = GetReShadeLoader();
            var loaderData = GetLoadingData();
            var loaderDataSize = Marshal.SizeOf<LoadingData>();

            if (!File.Exists(loaderData.LoadPath))
                return;

            TryUpdateIni(gameBiz);

            _logger.LogInformation("[ReShade Injection Begin]");
            var hProcess = gameProcess.Handle;
            var remoteVa = Kernel32.VirtualAllocEx(hProcess, 0, loaderStub.Length + loaderDataSize,
                Kernel32.MEM_ALLOCATION_TYPE.MEM_COMMIT | Kernel32.MEM_ALLOCATION_TYPE.MEM_RESERVE,
                Kernel32.MEM_PROTECTION.PAGE_EXECUTE_READWRITE);
            if (remoteVa == 0)
            {
                _logger.LogError($"Could not allocate memory in remote process ({Marshal.GetLastWin32Error()}: {Marshal.GetLastPInvokeErrorMessage()})");
                return;
            }

            var loaderBytes = StructToByteArray(loaderData);
            var toWrite = loaderStub.Concat(loaderBytes).ToArray();

            Kernel32.WriteProcessMemory(hProcess, remoteVa, toWrite, toWrite.Length, out var bytesWritten);

            var loaderDataRemote = remoteVa.ToInt64() + loaderStub.Length;
            using var hThread = Kernel32.CreateRemoteThread(hProcess, null, 0, remoteVa, (IntPtr)loaderDataRemote, 0, out var threadId);
            if (hThread == 0)
            {
                _logger.LogError($"Failed to spawn thread ({Marshal.GetLastWin32Error()}: {Marshal.GetLastPInvokeErrorMessage()})");
            }
            else
            {
                hThread.Wait();
                Kernel32.GetExitCodeThread(hThread, out var threadExitCode);
                _logger.LogInformation($"Remote thread completed with code {threadExitCode}");
            }

            Kernel32.VirtualFreeEx(hProcess, remoteVa, 0, Kernel32.MEM_ALLOCATION_TYPE.MEM_RELEASE);

            _logger.LogInformation("[ReShade Injection End]");
        }

        private byte[] GetReShadeLoader()
        {
            return new byte[]
            {
                // push rbx
                0x40, 0x53,
                
                // sub rsp, 0x20
                0x48, 0x83, 0xEC, 0x20,
                
                // mov rbx, rcx
                0x48, 0x8B, 0xD9,
                
                // lea rdx, [rcx+0x254] -env_var_value
                0x48, 0x8D, 0x91, 0x54, 0x02, 0x00, 0x00,

                // add rcx, 0x218 -env_var_name
                0x48, 0x81, 0xC1, 0x18, 0x02, 0x00, 0x00,

                // call qword ptr[rbx+0x258] -SetEnvironmentVariableW
                0xFF, 0x93, 0x58, 0x02, 0x00, 0x00,

                // mov rax, [rbx+0x210]
                0x48, 0x8B, 0x83, 0x10, 0x02, 0x00, 0x00,
                
                // mov rcx, rbx -load_path
                0x48, 0x8B, 0xCB,

                // call rax -LoadLibraryW
                0xFF, 0xD0,

                // test rax, rax
                0x48, 0x85, 0xC0,

                // jnz 0xF
                0x75, 0x0F,
                
                // mov rax, [rbx+0x208] -GetLastError
                0x48, 0x8B, 0x83, 0x08, 0x02, 0x00, 0x00,
                
                // add rsp, 0x20
                0x48, 0x83, 0xC4, 0x20,

                // pop rbx
                0x5B,
                
                // jmp rax
                0x48, 0xFF, 0xE0,

                // xor eax, eax
                0x33, 0xC0,
                
                // add rsp, 0x20
                0x48, 0x83, 0xC4, 0x20,
                
                // pop rbx
                0x5B,

                // ret
                0xC3
            };
        }

        private LoadingData GetLoadingData()
        {
            var kernel32 = Kernel32.GetModuleHandle("kernel32.dll");
            var pLoadLibraryW = Kernel32.GetProcAddress(kernel32, "LoadLibraryW");
            var pGetLastError = Kernel32.GetProcAddress(kernel32, "GetLastError");
            var pSetEnvironmentVariableW = Kernel32.GetProcAddress(kernel32, "SetEnvironmentVariableW");

            
            var loaderPath = Path.Combine(_currentPath, "ReShade64.dll");

            return new LoadingData
            {
                LoadPath = loaderPath,
                GetLastError = pGetLastError,
                LoadLibraryW = pLoadLibraryW,
                EnvVarName = "RESHADE_DISABLE_LOADING_CHECK",
                EnvVarValue = "1",
                SetEnvironmentVariableW = pSetEnvironmentVariableW
            };

        }

        private static byte[] StructToByteArray<T>(T structData) where T : struct
        {
            int size = Marshal.SizeOf(structData);
            byte[] byteArray = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(structData, ptr, false);
                Marshal.Copy(ptr, byteArray, 0, size);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            return byteArray;
        }

        private void TryUpdateIni(GameBiz gameBiz)
        {
            Directory.CreateDirectory("ScreenShot");
            var gamePath = _gameService.GetGameInstallPath(gameBiz);
            var iniPath = Path.Combine(gamePath, "ReShade.ini");

            if (!File.Exists(iniPath))
            {
                CreateIni(gamePath);
                return;
            }

        }

        private void CreateIni(string gamePath)
        {
            var reshadePath = Path.Combine(_currentPath, "ReShade");

            StringBuilder sb = new StringBuilder();
            
            sb.AppendLine("[ADDON]");
            sb.AppendLine($"AddonPath={Path.Combine(reshadePath, "reshade-shaders", "Addons")}");
            sb.AppendLine("DisabledAddons=");
            sb.AppendLine();

            sb.AppendLine("[DEPTH]");
            sb.AppendLine("DepthCopyAtClearIndex=0");
            sb.AppendLine("DepthCopyBeforeClears=0");
            sb.AppendLine("UseAspectRatioHeuristics=1");
            sb.AppendLine();

            sb.AppendLine("[GENERAL]");
            sb.AppendLine($"EffectSearchPaths={Path.Combine(reshadePath, "reshade-shaders", "Addons")}");
            sb.AppendLine("PerformanceMode=0");
            sb.AppendLine("PreprocessorDefinitions=RESHADE_DEPTH_LINEARIZATION_FAR_PLANE=1000.0,RESHADE_DEPTH_INPUT_IS_UPSIDE_DOWN=1,RESHADE_DEPTH_INPUT_IS_REVERSED=1,RESHADE_DEPTH_INPUT_IS_LOGARITHMIC=0\r\n");
            sb.AppendLine($"PresetPath={Path.Combine(reshadePath, "Presets", "Mod OFF.ini")}");
            sb.AppendLine("PresetTransitionDelay=995");
            sb.AppendLine("SkipLoadingDisabledEffects=0");
            sb.AppendLine($"TextureSearchPaths={Path.Combine(reshadePath, "reshade-shaders", "Textures")}");
            sb.AppendLine();

            sb.AppendLine("[INPUT]");
            sb.AppendLine("ForceShortcutModifiers=1");
            sb.AppendLine("InputProcessing=2");
            sb.AppendLine("KeyEffects=189,0,0,0");
            sb.AppendLine("KeyNextPreset=0,0,0,0");
            sb.AppendLine("KeyOverlay=36,0,0,0");
            sb.AppendLine("KeyPerformanceMode=80,0,0,0");
            sb.AppendLine("KeyPreviousPreset=0,0,0,0");
            sb.AppendLine("KeyReload=187,0,0,0");
            sb.AppendLine("KeyScreenshot=44,0,0,0");
            sb.AppendLine();

            sb.AppendLine("[OVERLAY]");
            sb.AppendLine("ClockFormat=0");
            sb.AppendLine("FPSPosition=1");
            sb.AppendLine("NoFontScaling=0");
            sb.AppendLine("SaveWindowState=0");
            sb.AppendLine("ShowClock=0");
            sb.AppendLine("ShowForceLoadEffectsButton=1");
            sb.AppendLine("ShowFPS=0");
            sb.AppendLine("ShowFrameTime=0");
            sb.AppendLine("ShowScreenshotMessage=1");
            sb.AppendLine("TutorialProgress=4");
            sb.AppendLine("VariableListHeight=300.000000");
            sb.AppendLine("VariableListUseTabs=0");
            sb.AppendLine();

            sb.AppendLine("[SCREENSHOT]");
            sb.AppendLine("ClearAlpha=1");
            sb.AppendLine("FileFormat=1");
            sb.AppendLine("FileNamingFormat=0");
            sb.AppendLine("JPEGQuality=90");
            sb.AppendLine("SaveBeforeShot=0");
            sb.AppendLine("SaveOverlayShot=0");
            sb.AppendLine($"SavePath={Path.Combine(reshadePath, "ScreenShot")}");
            sb.AppendLine("SavePresetFile=0");
            sb.AppendLine();

            sb.AppendLine("[STYLE]");
            sb.AppendLine("Alpha=1.000000");
            sb.AppendLine("ChildRounding=0.000000");
            sb.AppendLine("ColFPSText=1.000000,1.000000,0.784314,1.000000");
            sb.AppendLine("EditorFont=C:\\Windows\\Fonts\\segoeuib.ttf");
            sb.AppendLine("EditorFontSize=18");
            sb.AppendLine("EditorStyleIndex=0");
            sb.AppendLine("Font=C:\\Windows\\Fonts\\segoeuib.ttf");
            sb.AppendLine("FontSize=18");
            sb.AppendLine("FPSScale=1.000000");
            sb.AppendLine("FrameRounding=0.000000");
            sb.AppendLine("GrabRounding=0.000000");
            sb.AppendLine("PopupRounding=0.000000");
            sb.AppendLine("ScrollbarRounding=0.000000");
            sb.AppendLine("StyleIndex=2");
            sb.AppendLine("TabRounding=4.000000");
            sb.AppendLine("WindowRounding=0.000000");

            var iniPath = Path.Combine(gamePath, "Reshade.ini");
            File.WriteAllText(iniPath, sb.ToString());
        }

    }
}
