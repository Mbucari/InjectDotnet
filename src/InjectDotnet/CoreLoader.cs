using System.Collections.Generic;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using System.Text;
using System.Linq;

namespace InjectDotnet;

internal class CoreLoader : IManagedLoader
{
	public nint Loader { get; private init; }
	public nint Parameter { get; private init; }
	private const int MAX_PATH = 260;

	public static CoreLoader Create(Process target, string runtimeConfig, string dllToInject, string assemblyQualifiedTypeName, string method, ReadOnlySpan<byte> argument, bool entryPoint)
	{
		if (!File.Exists(runtimeConfig))
			throw new ArgumentException($"{nameof(runtimeConfig)} file not found");
		if (!File.Exists(dllToInject))
			throw new ArgumentException($"{nameof(dllToInject)} file not found");

		runtimeConfig = Path.GetFullPath(runtimeConfig);
		dllToInject = Path.GetFullPath(dllToInject);

		string? hostPath = target.GetHostFxrLib();
		if (hostPath is null)
		{
			//Target is not a .NET process, so find the appropriate hostfxr.dll to load the CLR
			JsonNode options
				= JsonNode.Parse(File.ReadAllText(runtimeConfig))?["runtimeOptions"]
				?? throw new KeyNotFoundException($"Could not 'runtimeOptions' from runtimeConfig.json");

			Version? runtimeVersion
				= tryGetVersion(options["framework"])
				?? options["frameworks"]?.AsArray().Select(tryGetVersion).FirstOrDefault(v => v is not null)
				?? throw new KeyNotFoundException($"Could not determine the Microsoft.NETCore.App runtime from runtimeConfig.json");

			Version installedRuntimeVer
				= GetInstalledFrameworks().FirstOrDefault(v => v >= runtimeVersion)
				?? throw new DirectoryNotFoundException($"Could not find installed Microsoft.NETCore.App runtime with version >= {runtimeVersion:3}");

			hostPath
				= GetHostfxrPath(installedRuntimeVer)
				?? throw new FileNotFoundException($"Could not find the {PLATFORM} hostfxr.dll for runtime version {runtimeVersion:3}");
		}
		else if (entryPoint)
			throw new ArgumentException("Cannot inject into a .NET target at startup.", nameof(entryPoint));

		var k3dMod = target.GetKernel32();

		CoreParameter? param = null;
		nint? pLoader = null;
		nint? pParams = null;
		try
		{
			param = new CoreParameter(k3dMod)
			{
				fnEntryPoint = entryPoint ? target.MainModule?.EntryPointAddress ?? IntPtr.Zero : 0,
				str_runtimeconfig = target.WriteMemory(runtimeConfig),
				str_dll_path = target.WriteMemory(dllToInject),
				str_method_name = target.WriteMemory(method),
				str_type = target.WriteMemory(assemblyQualifiedTypeName),
				str_hostfxr_path = target.WriteMemory(hostPath),
				str_Config_name = target.WriteMemory(Encoding.ASCII.GetBytes("hostfxr_initialize_for_runtime_config")),
				str_GetDelegate_name = target.WriteMemory(Encoding.ASCII.GetBytes("hostfxr_get_runtime_delegate")),
				str_Close_name = target.WriteMemory(Encoding.ASCII.GetBytes("hostfxr_close")),
				args = target.WriteMemory(argument),
				sz_args = argument.Length
			};
			pLoader = target.WriteMemory(DOTNET_LOADER_ASM, Native.MemoryProtection.Execute);
			pParams = target.WriteMemory(param.Value);
			return new CoreLoader { Loader = pLoader.Value, Parameter = pParams.Value };
		}
		catch
		{
			if (param is CoreParameter p)
			{
				target.Free(p.str_runtimeconfig);
				target.Free(p.str_dll_path);
				target.Free(p.str_method_name);
				target.Free(p.str_type);
				target.Free(p.str_hostfxr_path);
				target.Free(p.str_Config_name);
				target.Free(p.str_GetDelegate_name);
				target.Free(p.str_Close_name);
				target.Free(p.args);
			}
			if (pLoader.HasValue)
				target.Free(pLoader.Value);
			if (pParams.HasValue)
				target.Free(pParams.Value);
			throw;
		}

		static Version? tryGetVersion(JsonNode? framework)
			=> framework?["name"]?.GetValue<string>() == "Microsoft.NETCore.App" &&
				framework["version"]?.GetValue<string>() is string vStr &&
				Version.TryParse(vStr, out var v)
				? v : null;
	}

	/// <summary>
	/// Get installed NETCore.App framework versions
	/// </summary>
	public static IEnumerable<Version> GetInstalledFrameworks()
	{
		var pf86 = Environment.GetEnvironmentVariable("ProgramW6432");
		var versions = Directory.GetDirectories($@"{pf86}\dotnet\packs\Microsoft.NETCore.App.Host.win-{PLATFORM}");

		foreach (var v in versions)
		{
			var dir = Path.GetFileName(v);
			if (Version.TryParse(dir, out var version))
				yield return version;
		}
	}

	private static unsafe string? GetHostfxrPath(Version? version)
	{
		if (version is null) return null;

		var pf86 = Environment.GetEnvironmentVariable("ProgramW6432");
		var nethostPath = $@"{pf86}\dotnet\packs\Microsoft.NETCore.App.Host.win-{PLATFORM}\{version:3}\runtimes\win-{PLATFORM}\native\nethost.dll";

		if (!File.Exists(nethostPath) || !NativeLibrary.TryLoad(nethostPath, out var hLib))
			return null;
		try
		{
			if (!NativeLibrary.TryGetExport(hLib, "get_hostfxr_path", out var hProc))
				return null;

			int buff_sz = MAX_PATH + 1;
			Span<char> buff = new char[buff_sz];

			var get_hostfxr_path = (delegate* unmanaged<char*, ref int, nint, void>)hProc;

			fixed (char* c = buff)
				get_hostfxr_path(c, ref buff_sz, 0);

			return new string(buff.Slice(0, buff_sz - 1));
		}
		finally
		{
			NativeLibrary.Free(hLib);
		}
	}

	#region Loader Parameter
	[StructLayout(LayoutKind.Explicit)]
	private struct CoreParameter
	{
		[FieldOffset(0)]
		readonly nint fnConfig;
		[FieldOffset(8)]
		readonly nint fnGetDelegate;
		[FieldOffset(0x10)]
		readonly nint fnClose;
		[FieldOffset(0x18)]
		readonly nint fnVirtualFree;
		[FieldOffset(0x20)]
		readonly nint fnLoadLibrary;
		[FieldOffset(0x28)]
		readonly nint fnGetProcAddress;
		[FieldOffset(0x30)]
		public nint fnEntryPoint;
		[FieldOffset(0x38)]
		readonly nint _context;
		[FieldOffset(0x40)]
		readonly nint _delegate;
		[FieldOffset(0x48)]
		readonly nint _method_fn;

		[FieldOffset(0x50)]
		public nint str_runtimeconfig;
		[FieldOffset(0x58)]
		public nint str_dll_path;
		[FieldOffset(0x60)]
		public nint str_type;
		[FieldOffset(0x68)]
		public nint str_method_name;
		[FieldOffset(0x70)]
		public nint str_hostfxr_path;
		[FieldOffset(0x78)]
		public nint str_Config_name;
		[FieldOffset(0x80)]
		public nint str_GetDelegate_name;
		[FieldOffset(0x88)]
		public nint str_Close_name;
		[FieldOffset(0x90)]
		public nint args;
		[FieldOffset(0x98)]
		public int sz_args;
		[FieldOffset(0xa0)]
		readonly nint fnExitThread;
		public CoreParameter(ProcessModule k3dMod) : this()
		{
			fnVirtualFree = k3dMod.GetProcAddress("VirtualFree");
			fnLoadLibrary = k3dMod.GetProcAddress("LoadLibraryW");
			fnGetProcAddress = k3dMod.GetProcAddress("GetProcAddress");
			fnExitThread = k3dMod.GetProcAddress("ExitThread");
		}
	}
	#endregion

	#region Loader
#if X64
	private static readonly string PLATFORM = "x64";
	//Loads dotnet runtime, calls the injected dll, and then frees InjectParams and all its fields
	//Sets thread exit code to method's return value
	private static readonly byte[] DOTNET_LOADER_ASM = new byte[]
{
 0x48, 0x83, 0xEC, 0x38,				//sub rsp, 0x38
 0x48, 0x89, 0xCD,						//mov rbp, rcx | Store InjectParams 1 in rbp
 0x48, 0x8B, 0x4D, 0x70,				//mov rcx, [Arg.str_hostfxr_path]
 0xFF, 0x55, 0x20,						//call [fnLoadLibrary]
 0x48, 0x89, 0xC3,						//mov rbx,rax
 0x31, 0xF6,							//xor esi,esi 
 //GETPROC:
 0x48, 0x89, 0xD9,						//mov rcx,rbx
 0x48, 0x8B, 0x54, 0xF5, 0x78,			//mov rdx,[Arg + rsi * 8 + 78]
 0xFF, 0x55, 0x28,						//call [fnGetProcAddress]
 0x48, 0x89, 0x44, 0xF5, 0x00,			//mov [Arg + rsi * 8],rax
 0xFF, 0xC6,							//inc esi
 0x83, 0xFE, 0x02,						//cmp esi,2
 0x7E, 0xE9,							//jle GETPROC
 0x4C, 0x8D, 0x45, 0x38,				//mov r8, [Arg._context] 
 0x48, 0x31, 0xD2,						//xor rdx, rdx
 0x48, 0x8B, 0x4D, 0x50,				//mov rcx, [Arg.str_runtimeconfig]
 0xFF, 0x55, 0x00,						//call [Arg.fnConfig]
 0x48, 0x85, 0xC0,						//test rax,rax
 0x74, 0x14,							//je GETDELEGATE
 0x48, 0x83, 0xF8, 0x01,				//cmp rax,1
 0x74, 0x0e,							//je GETDELEGATE
 0x48, 0x83, 0xF8, 0x02,				//cmp rax,2
 0x74, 0x08,							//je GETDELEGATE
 0x89, 0xC1,							//mov ecx,eax
 0xFF, 0x95, 0xA0, 0x00, 0x00, 0x00,	//call [fnExitThread]
//GETDELEGATE:
 0x4C, 0x8D, 0x45, 0x40,				//mov r8, [Arg._delegate]
 0x48, 0x31, 0xD2,						//xor rdx, rdx
 0xB2, 0x05,							//mov dl, hostfxr_delegate_type.hdt_load_assembly_and_get_function_pointer
 0x48, 0x8B, 0x4D, 0x38,				//mov rcx [Arg._context]
 0xFF, 0x55, 0x08,						//call [Arg.fnGetDelegate]
 0x48, 0x85, 0xC0,						//test rax,rax
 0x74, 0x08,							//je CLOSECONTEXT
 0x89, 0xC1,							//mov ecx,eax
 0xFF, 0x95, 0xA0, 0x00, 0x00, 0x00,	//call [fnExitThread]
 //CLOSECONTEXT
 0x48, 0x8B, 0x4D, 0x38,				//mov rcx, [Arg._context]
 0xFF, 0x55, 0x10,						//call [Arg.fnClose]
 0x48, 0x8D, 0x45, 0x48,				//lea rax, [Arg._method_fn]
 0x48, 0x89, 0x44, 0x24, 0x28,			//mov [rsp+28], rax
 0x4D, 0x31, 0xC9,						//xor r9, r9
 0x4C, 0x89, 0x4C, 0x24, 0x20,			//mov [rsp+20], r9
 0x4C, 0x8B, 0x45, 0x68,				//mov r8, [Arg.str_method_name]
 0x48, 0x8B, 0x55, 0x60,				//mov rdx, [Arg.str_type]
 0x48, 0x8B, 0x4D, 0x58,				//mov rcx, [Arg.str_dll_path]
 0xFF, 0x55, 0x40,						//call [Arg._delegate]
 0x48, 0x8B, 0x95, 0x98, 0, 0, 0,		//mov rdx,[Arg.sz_args]
 0x48, 0x8B, 0x8D, 0x90, 0, 0, 0,		//mov rcx,[Arg.args]
 0xFF, 0x55, 0x48,						//call [Arg._method_fn]
 0x8B, 0xF8,							//mov edi, eax
 0x48, 0x33, 0xF6,						//xor rsi, rsi
 //FREE:
 0x41, 0xB8, 0x00, 0x80, 0, 0,			//mov r8d, MEM_RELEASE
 0x48, 0x31, 0xD2,						//xor rdx, rdx
 0x48, 0x8B, 0x4C, 0xF5, 0x50,			//mov rcx, [Arg + rsi * 8 + 0x50]
 0xFF, 0x55, 0x18,						//call [Arg.fnVirtualFree]
 0xFF, 0xC6,							//inc esi
 0x83, 0xFE, 0x09,						//cmp esi,9
 0x75, 0xE8,							//jne FREE
 0x48, 0x8B, 0x75, 0x30,				//mov rsi, [Arg.fnEntryPoint]
 0x41, 0xB8, 0x00, 0x80, 0, 0,			//mov r8d, MEM_RELEASE
 0x48, 0x31, 0xD2,						//xor rdx, rdx
 0x48, 0x89, 0xE9,						//mov rcx, (Arg)
 0xFF, 0x55, 0x18,						//call [Arg.fnVirtualFree]
 0x8B, 0xC7,							//mov eax, edi
 0x48, 0x83, 0xC4, 0x38,				//add rsp, 0x38
 0x48, 0x85, 0xF6,						//test rsi,rsi
 0x74, 0x02,							//je RETURN
 0xFF, 0xE6,							//jmp [EntryPoint]
 0xC3									//ret
};
#elif X86
	private static readonly string PLATFORM = "x86";
	//Loads dotnet runtime, calls the injected dll, and then frees InjectParams and all its fields
	//Sets thread exit code to method's return value
	private static readonly byte[] DOTNET_LOADER_ASM = new byte[]
{
 0x8B, 0x6C, 0x24, 0x04,		// mov ebp, [esp+0x4] | Store InjectParams 1 in ebp
 0xFF, 0x75, 0x70,				//push [Arg.str_hostfxr_path]
 0xFF, 0x55, 0x20,				//call [fnLoadLibrary]
 0x89, 0xC7,					//mov edi,eax
 0x31, 0xF6,					//xor esi,esi
 //GETPROC:
 0xFF, 0x74, 0xF5, 0x78,		//push [Arg + esi * 8 + 78]
 0x57,							//push edi
 0xFF, 0x55, 0x28,				//call [fnGetProcAddress]
 0x89, 0x44, 0xF5, 0x00,		//mov [Arg + esi * 8],eax
 0x46,							//inc esi
 0x83, 0xFE, 0x02,				//cmp esi,2
 0x7E, 0xEE,					//jle GETPROC


 0x8D, 0x45, 0x38,				//lea eax, [Arg._context] 
 0x50,							//push eax
 0x6A, 0x00,					//push 0
 0xFF, 0x75, 0x50,				//push [Arg.str_runtimeconfig]
 0xFF, 0x55, 0x00,				//call [Arg.fnConfig]
 0x85, 0xC0,					//test rax,rax
 0x74, 0x11,					//je GETDELEGATE
 0x83, 0xF8, 0x01,				//cmp rax,1
 0x74, 0x0c,					//je GETDELEGATE
 0x83, 0xF8, 0x02,				//cmp rax,2
 0x74, 0x07,					//je GETDELEGATE
 0x50,							//push eax
 0xFF, 0x95, 0xA0, 0x00, 0x00, 0x00,	//call [fnExitThread]
//GETDELEGATE:
 0x8D, 0x45, 0x40,				//lea eax, [Arg._delegate]
 0x50,							//push eax
 0x6A, 0x05,					//push hostfxr_delegate_type.hdt_load_assembly_and_get_function_pointer
 0xFF, 0x75, 0x38,				//push [Arg._context]
 0xFF, 0x55, 0x08,				//call [Arg.fnGetDelegate]
 0x85, 0xC0,					//test rax,rax
 0x74, 0x07,					//je CLOSECONTEXT
 0x50,							//push eax
 0xFF, 0x95, 0xA0, 0x00, 0x00, 0x00,	//call [fnExitThread]
 //CLOSECONTEXT
 0xFF, 0x75, 0x38,				//push [Arg._context]
 0xFF, 0x55, 0x10,				//call [Arg.fnClose]
 0x8D, 0x45, 0x48,				//lea eax, [Arg._method_fn]
 0x50,							//push eax
 0x6A, 0x00,					//push 0
 0x6A, 0x00,					//push 0
 0xFF, 0x75, 0x68,				//push [Arg.str_method_name]
 0xFF, 0x75, 0x60,				//push [Arg.str_type]
 0xFF, 0x75, 0x58,				//push [Arg.str_dll_path]
 0xFF, 0x55, 0x40,				//call [Arg._delegate]
 0xFF, 0xB5, 0x98, 0, 0, 0,		//push [Arg.sz_args]
 0xFF, 0xB5, 0x90, 0, 0, 0,		//push [Arg.args]
 0xFF, 0x55, 0x48,				//call [Arg._method_fn]
 0x8B, 0xF8,					//mov edi, eax
 0x31, 0xF6,					//xor esi, esi
//FREE:
 0x68, 0x00, 0x80, 0, 0,		//push MEM_RELEASE
 0x6A, 0x00,					//push 0
 0xFF, 0x74, 0xF5, 0x50,		//push [Arg + esi * 8 + 0x50]
 0xFF, 0x55, 0x18,				//call [Arg.fnVirtualFree]
 0x46,							//inc esi
 0x83, 0xFE, 0x09,				//cmp esi, 9
 0x75, 0xEC,					//jne FREE 
 0x8B, 0x75, 0x30,				//mov esi, [Arg.fnEntryPoint]
 0x68, 0x00, 0x80, 0, 0,		//push MEM_RELEASE
 0x6A, 0x00,					//push 0
 0x55,							//push (Arg)
 0xFF, 0x55, 0x18,				//call [Arg.fnVirtualFree]
 0x8B, 0xC7,					//mov eax, edi
 0x83, 0xC4, 0x1C,				//add esp, 0x1c
 0x83, 0xFE, 0x00,				//cmp esi, 0
 0x74, 0x02,					//je [Return]
 0xFF, 0xE6,					//jmp [EntryPoint]
 0xC3,							//ret
};
#endif
	#endregion
}
