using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;

namespace InjectDotnet;

public static class Injector
{
	private const int MAX_PATH = 260;

	#region Loader

#if X64
	private static readonly string PLATFORM = "x64";
	//Loads dotnet runtime, calls the injected dll, and then frees InjectParams and all its fields
	//Sets thread exit code to method's return value
	private static readonly byte[] DOTNET_LOADER_ASM = new byte[]
{
 0x48, 0x83, 0xEC, 0x38,				//sub rsp, 0x38
 0x48, 0x89, 0xCD,						//mov rbp, rcx | Store InjectParams 1 in rbp
 0x4C, 0x8D, 0x45, 0x28,				//mov r8, [Arg._context] 
 0x48, 0x31, 0xD2,						//xor rdx, rdx
 0x48, 0x8B, 0x4D, 0x40,				//mov rcx, [Arg.str_runtimeconfig]
 0xFF, 0x55, 0x00,						//call [Arg.fnConfig]
 0x4C, 0x8D, 0x45, 0x30,				//mov r8, [Arg._delegate]
 0x48, 0x31, 0xD2,						//xor rdx, rdx
 0xB2, 0x05,							//mov dl, hostfxr_delegate_type.hdt_load_assembly_and_get_function_pointer
 0x48, 0x8B, 0x4D, 0x28,				//mov rcx [Arg._context]
 0xFF, 0x55, 0x08,						//call [Arg.fnGetDelegate]
 0x48, 0x8B, 0x4D, 0x28,				//mov rcx, [Arg._context]
 0xFF, 0x55, 0x10,						//call [Arg.fnClose]
 0x48, 0x8D, 0x45, 0x38,				//lea rax, [Arg._method_fn]
 0x48, 0x89, 0x44, 0x24, 0x28,			//mov [rsp+28], rax
 0x4D, 0x31, 0xC9,						//xor r9, r9
 0x4C, 0x89, 0x4C, 0x24, 0x20,			//mov [rsp+20], r9
 0x4C, 0x8B, 0x45, 0x58,				//mov r8, [Arg.str_method_name]
 0x48, 0x8B, 0x55, 0x50,				//mov rdx, [Arg.str_type]
 0x48, 0x8B, 0x4D, 0x48,				//mov rcx, [Arg.str_dll_path]
 0xFF, 0x55, 0x30,						//call [Arg._delegate]
 0x48, 0x8B, 0x55, 0x68,				//mov rdx,[Arg.sz_args]
 0x48, 0x8B, 0x4D, 0x60,				//mov rcx,[Arg.args]
 0xFF, 0x55, 0x38,						//call [Arg._method_fn]
 0x8B, 0xF8,							//mov edi, eax
 0x48, 0x33, 0xF6,						//xor rsi, rsi
 //FREE:
 0x41, 0xB8, 0x00, 0x80, 0x00, 0x00,	//mov r8d, MEM_RELEASE
 0x48, 0x31, 0xD2,						//xor rdx, rdx
 0x48, 0x8B, 0x4C, 0xF5, 0x40,			//mov rcx, [Arg + rsi * 8 + 0x40]
 0xFF, 0x55, 0x18,						//call [Arg.fnVirtualFree]
 0xFF, 0xC6,							//inc esi
 0x83, 0xFE, 0x05,						//cmp esi,5
 0x75, 0xE8,							//jne FREE
 0x41, 0xB8, 0x00, 0x80, 0x00, 0x00,	//mov r8d, MEM_RELEASE
 0x48, 0x31, 0xD2,						//xor rdx, rdx
 0x48, 0x89, 0xE9,						//mov rcx, (Arg)
 0xFF, 0x55, 0x18,						//call [Arg.fnVirtualFree]
 0x8B, 0xC7,							//mov eax, edi
 0x48, 0x83, 0xC4, 0x38,				//add rsp, 0x38
 0xC3									//ret
};

#else
	private static readonly string PLATFORM = "x86";
	//Loads dotnet runtime, calls the injected dll, and then frees InjectParams and all its fields
	//Sets thread exit code to method's return value
	private static readonly byte[] DOTNET_LOADER_ASM = new byte[]
{
 0x8B, 0x6C, 0x24, 0x04,		// mov ebp, [esp+0x4] | Store InjectParams 1 in ebp
 0x8D, 0x45, 0x28,				//lea eax, [Arg._context] 
 0x50,							//push eax
 0x6A, 0x00,					//push 0
 0xFF, 0x75, 0x40,				//push [Arg.str_runtimeconfig]
 0xFF, 0x55, 0x00,				//call [Arg.fnConfig]
 0x8D, 0x45, 0x30,				//lea eax, [Arg._delegate]
 0x50,							//push eax
 0x6A, 0x05,					//push hostfxr_delegate_type.hdt_load_assembly_and_get_function_pointer
 0xFF, 0x75, 0x28,				//push [Arg._context]
 0xFF, 0x55, 0x08,				//call [Arg.fnGetDelegate]
 0xFF, 0x75, 0x28,				//push [Arg._context]
 0xFF, 0x55, 0x10,				//call [Arg.fnClose]
 0x8D, 0x45, 0x38,				//lea eax, [Arg._method_fn]
 0x50,							//push eax
 0x6A, 0x00,					//push 0
 0x6A, 0x00,					//push 0
 0xFF, 0x75, 0x58,				//push [Arg.str_method_name]
 0xFF, 0x75, 0x50,				//push [Arg.str_type]
 0xFF, 0x75, 0x48,				//push [Arg.str_dll_path]
 0xFF, 0x55, 0x30,				//call [Arg._delegate]
 0xFF, 0x75, 0x68,				//push [Arg.sz_args]
 0xFF, 0x75, 0x60,				//push [Arg.args]
 0xFF, 0x55, 0x38,				//call [Arg._method_fn]
 0x8B, 0xF8,					//mov edi, eax
 0x31, 0xF6,					//xor esi, esi
//FREE:
 0x68, 0x00, 0x80, 0x00, 0x00,	//push MEM_RELEASE
 0x6A, 0x00,					//push 0
 0xFF, 0x74, 0xF5, 0x40,		//push [Arg + esi * 8 + 0x40]
 0xFF, 0x55, 0x18,				//call [Arg.fnVirtualFree]
 0x46,							//inc esi
 0x83, 0xFE, 0x05,				//cmp esi, 5
 0x75, 0xEC,					//jne FREE
 0x68, 0x00, 0x80, 0x00, 0x00,	//push MEM_RELEASE
 0x6A, 0x00,					//push 0
 0x55,							//push (Arg)
 0xFF, 0x55, 0x18,				//call [Arg.fnVirtualFree]
 0x8B, 0xC7,					//mov eax, edi
 0x83, 0xC4, 0x1C,				//add esp, 0x1c
 0xC3							//ret
};
#endif

#endregion


	/// <summary>
	/// Inject a .NET Core dll into an Win32 or Win64 native process.
	/// </summary>
	/// <typeparam name="T">Struct type to be passed to the injected dll</typeparam>
	/// <param name="target">The process into which the dotnet dll will be injected</param>
	/// <param name="runtimeconfig">Filename of the .runtimeconfig.json file for the dll to be injected</param>
	/// <param name="dllToInject">Filename of the dll to be injected</param>
	/// <param name="asssemblyQualifiedTypeName">Full <see cref="Type.AssemblyQualifiedName"/> type name</param>
	/// <param name="method">Name of the static method in the injected dll to be invoked upon injection. Must have signature <see cref="int"/>(<see cref="IntPtr"/>, <see cref="int"/>)</param>
	/// <param name="argument">Argument to be passed to the method. All reference types must be written to the <paramref name="target"/> process's memory, and the dll must free that memory.</param>
	/// <param name="waitForReturn">Whether to wait for <paramref name="method"/> to return</param>
	/// <returns>If <paramref name="waitForReturn"/> is true, the value returned by <paramref name="method"/>. Otherwise null.</returns>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="InvalidProgramException"></exception>
	/// <exception cref="DirectoryNotFoundException"></exception>
	/// <exception cref="FileNotFoundException"></exception>
	/// <exception cref="DllNotFoundException"></exception>
	public static int? Inject<T>(Process target, string runtimeconfig, string dllToInject, string asssemblyQualifiedTypeName, string method, T argument, bool waitForReturn = true)
		where T : struct
	{
		var size = Marshal.SizeOf<T>();
		Span<byte> argBts = new byte[size];
		MemoryMarshal.Write(argBts, ref argument);
		return Inject(target, runtimeconfig, dllToInject, asssemblyQualifiedTypeName, method, argBts, waitForReturn);
	}

	/// <summary>
	/// Inject a .NET Core dll into an Win32 or Win64 native process.
	/// </summary>
	/// <param name="target">The process into which the dotnet dll will be injected</param>
	/// <param name="runtimeconfig">Filename of the .runtimeconfig.json file for the dll to be injected</param>
	/// <param name="dllToInject">Filename of the dll to be injected</param>
	/// <param name="asssemblyQualifiedTypeName">Full <see cref="Type.AssemblyQualifiedName"/> type name</param>
	/// <param name="method">Name of the static method in the injected dll to be invoked upon injection. Must have signature <see cref="int"/>(<see cref="IntPtr"/>, <see cref="int"/>)</param>
	/// <param name="argument">Argument to be passed to the method</param>
	/// <param name="waitForReturn">Whether to wait for <paramref name="method"/> to return</param>
	/// <returns>If <paramref name="waitForReturn"/> is true, the value returned by <paramref name="method"/>. Otherwise null.</returns>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="InvalidProgramException"></exception>
	/// <exception cref="DirectoryNotFoundException"></exception>
	/// <exception cref="FileNotFoundException"></exception>
	/// <exception cref="DllNotFoundException"></exception>
	public static int? Inject(Process target, string runtimeconfig, string dllToInject, string asssemblyQualifiedTypeName, string method, string argument, bool waitForReturn = true)
	{
		var argBts = MemoryMarshal.AsBytes(argument.AsSpan());
		return Inject(target, runtimeconfig, dllToInject, asssemblyQualifiedTypeName, method, argBts, waitForReturn);
	}

	/// <summary>
	/// Inject a .NET Core dll into an Win32 or Win64 native process.
	/// </summary>
	/// <param name="target">The process into which the dotnet dll will be injected</param>
	/// <param name="runtimeconfig">Filename of the .runtimeconfig.json file for the dll to be injected</param>
	/// <param name="dllToInject">Filename of the dll to be injected</param>
	/// <param name="asssemblyQualifiedTypeName">Full <see cref="Type.AssemblyQualifiedName"/> type name</param>
	/// <param name="method">Name of the static method in the injected dll to be invoked upon injection. Must have signature <see cref="int"/>(<see cref="IntPtr"/>, <see cref="int"/>)</param>
	/// <param name="argument">Argument to be passed to the method</param>
	/// <param name="waitForReturn">Whether to wait for <paramref name="method"/> to return</param>
	/// <returns>If <paramref name="waitForReturn"/> is true, the value returned by <paramref name="method"/>. Otherwise null.</returns>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="InvalidProgramException"></exception>
	/// <exception cref="DirectoryNotFoundException"></exception>
	/// <exception cref="FileNotFoundException"></exception>
	/// <exception cref="DllNotFoundException"></exception>
	public static int? Inject(Process target, string runtimeconfig, string dllToInject, string asssemblyQualifiedTypeName, string method, ReadOnlySpan<byte> argument, bool waitForReturn = true)
	{
		if (!File.Exists(runtimeconfig))
			throw new ArgumentException($"{nameof(runtimeconfig)} file not found");
		if (!File.Exists(dllToInject))
			throw new ArgumentException($"{nameof(dllToInject)} file not found");

		if (JsonNode.Parse(File.ReadAllText(runtimeconfig))?["runtimeOptions"] is not JsonNode options)
			throw new KeyNotFoundException($"Could not 'runtimeOptions' from runtimeconfig.json");

		Version? runtimeVersion
			= tryGetVersion(options["framework"])
			?? options["frameworks"]?.AsArray().Select(tryGetVersion).FirstOrDefault(v => v is not null);

		if (runtimeVersion is null)
			throw new KeyNotFoundException($"Could not determine the Microsoft.NETCore.App runtime from runtimeconfig.json");

		if (GetInstalledFrameworks().FirstOrDefault(v => v >= runtimeVersion) is not Version installedRuntimeVer)
			throw new DirectoryNotFoundException($"Could not find installed Microsoft.NETCore.App runtime with version >= {runtimeVersion:3}");

		if (GetHosthostfxrPath(installedRuntimeVer) is not string hostPath)
			throw new FileNotFoundException($"Could not find the {PLATFORM} hostfxr.dll for runtime version {runtimeVersion:3}");

		if (target.LoadLibrary(hostPath) is not ProcessModule hostMod)
			throw new DllNotFoundException("Failed to load hostfxr.dll in the target process");

		var k3dMod = target.GetKernel32();

		InjectParams? param = null;
		IntPtr? loader = null;
		try
		{
			param = new InjectParams
			{
				fnConfig = hostMod.GetProcAddress("hostfxr_initialize_for_runtime_config"),
				fnGetDelegate = hostMod.GetProcAddress("hostfxr_get_runtime_delegate"),
				fnClose = hostMod.GetProcAddress("hostfxr_close"),
				fnVirtualFree = k3dMod.GetProcAddress("VirtualFree"),
				str_runtimeconfig = target.WriteMemory(runtimeconfig),
				str_dll_path = target.WriteMemory(dllToInject),
				str_method_name = target.WriteMemory(method),
				str_type = target.WriteMemory(asssemblyQualifiedTypeName),
				args = target.WriteMemory(argument),
				sz_args = argument.Length
			};

			loader = target.WriteMemory(DOTNET_LOADER_ASM, MemoryProtection.Execute);

			return target.Call(loader.Value, param.Value, waitForReturn);
		}
		catch
		{
			if (param is InjectParams p)
			{
				target.Free(p.str_runtimeconfig);
				target.Free(p.str_dll_path);
				target.Free(p.str_method_name);
				target.Free(p.str_type);
				target.Free(p.args);
			}
			if (loader is IntPtr l)
				target.Free(l);

			return null;
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

	private static unsafe string? GetHosthostfxrPath(Version? version)
	{
		if (version is null) return null;

		var pf86 = Environment.GetEnvironmentVariable("ProgramW6432");
		var nethostPath = $@"{pf86}\dotnet\packs\Microsoft.NETCore.App.Host.win-{PLATFORM}\{version:3}\runtimes\win-{PLATFORM}\native\nethost.dll";

		if (!File.Exists(nethostPath)) return null;
		if (!NativeLibrary.TryLoad(nethostPath, out var hlib)) return null;
		if (!NativeLibrary.TryGetExport(hlib, "get_hostfxr_path", out var hproc)) return null;

		int buff_sz = MAX_PATH + 1;
		Span<char> buff = new char[buff_sz];

		var get_hostfxr_path = (delegate* unmanaged<char*, ref int, nint, void>)hproc;

		fixed (char* c = buff)
			get_hostfxr_path(c, ref buff_sz, 0);

		NativeLibrary.Free(hlib);

		return new string(buff.Slice(0, buff_sz - 1));
	}
}
