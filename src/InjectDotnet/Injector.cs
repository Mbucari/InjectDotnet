using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;

namespace InjectDotnet
{
	public static class Injector
	{
		//Loads dotnet runtime, calls the injected dll, and then frees InjectParams and all its fields
		//Sets thread exit code to method's return value
		private static readonly byte[] DOTNET_LOADER_ASM;
		private const int MAX_PATH = 260;
		private static readonly string PLATFORM;

		static Injector()
		{
			if (Environment.Is64BitProcess)
			{
				PLATFORM = "x64";
				DOTNET_LOADER_ASM = new byte[]
{
0x48, 0x83, 0xEC, 0x48, 0x48, 0x89, 0xCD, 0x48, 0x8B, 0x4D, 0x40, 0x4C, 0x8D, 0x45, 0x28, 0x48,
 0x31, 0xD2, 0xFF, 0x55, 0x00, 0x48, 0x8B, 0x4D, 0x28, 0x48, 0x31, 0xD2, 0xB2, 0x05, 0x4C, 0x8D,
 0x45, 0x30, 0xFF, 0x55, 0x08, 0x48, 0x8B, 0x4D, 0x28, 0xFF, 0x55, 0x10, 0x48, 0x8D, 0x45, 0x38,
 0x48, 0x89, 0x44, 0x24, 0x28, 0x4D, 0x31, 0xC9, 0x4C, 0x89, 0x4C, 0x24, 0x20, 0x4C, 0x8B, 0x45,
 0x58, 0x48, 0x8B, 0x55, 0x50, 0x48, 0x8B, 0x4D, 0x48, 0xFF, 0x55, 0x30, 0x48, 0x8B, 0x4D, 0x60,
 0x48, 0x8B, 0x55, 0x68, 0xFF, 0x55, 0x38, 0x89, 0xC6, 0x4C, 0x8B, 0x65, 0x18, 0x4C, 0x8B, 0x6D,
 0x20, 0x31, 0xFF, 0x41, 0xB8, 0x00, 0x80, 0x00, 0x00, 0x48, 0x31, 0xD2, 0x48, 0x8B, 0x4C, 0xFD,
 0x40, 0x41, 0xFF, 0xD4, 0xFF, 0xC7, 0x83, 0xFF, 0x05, 0x75, 0xE8, 0x41, 0xB8, 0x00, 0x80, 0x00,
 0x00, 0x48, 0x31, 0xD2, 0x48, 0x89, 0xE9, 0x41, 0xFF, 0xD4, 0x89, 0xF1, 0x41, 0xFF, 0xD5
};
			}
			else
			{
				PLATFORM = "x86";
				DOTNET_LOADER_ASM = new byte[]
{
0x8B, 0x6C, 0x24, 0x04, 0x8D, 0x45, 0x28, 0x50, 0x33, 0xC0, 0x50, 0xFF, 0x75, 0x40, 0xFF, 0x55,
 0x00, 0x8D, 0x45, 0x30, 0x50, 0x6A, 0x05, 0xFF, 0x75, 0x28, 0xFF, 0x55, 0x08, 0xFF, 0x75, 0x28,
 0xFF, 0x55, 0x10, 0x8D, 0x45, 0x38, 0x50, 0x6A, 0x00, 0x6A, 0x00, 0xFF, 0x75, 0x58, 0xFF, 0x75,
 0x50, 0xFF, 0x75, 0x48, 0xFF, 0x55, 0x30, 0xFF, 0x75, 0x68, 0xFF, 0x75, 0x60, 0xFF, 0x55, 0x38,
 0x8B, 0xF8, 0x31, 0xF6, 0x68, 0x00, 0x80, 0x00, 0x00, 0x6A, 0x00, 0xFF, 0x74, 0xF5, 0x40, 0xFF,
 0x55, 0x18, 0x46, 0x83, 0xFE, 0x05, 0x75, 0xEC, 0x8B, 0x75, 0x20, 0x68, 0x00, 0x80, 0x00, 0x00,
 0x6A, 0x00, 0x55, 0xFF, 0x55, 0x18, 0x57, 0xFF, 0xD6
};
			}
		}

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

			var runtimes = JsonNode.Parse(File.ReadAllText(runtimeconfig))?["runtimeOptions"]?["frameworks"] as JsonArray;

			if (runtimes?.FirstOrDefault(r => r?["name"]?.GetValue<string>() == "Microsoft.NETCore.App")?["version"]?.GetValue<string>() is not string verStr
				|| !Version.TryParse(verStr, out var runtimeVersion))
				throw new InvalidProgramException($"{nameof(runtimeconfig)} contains no frameworks");

			if (GetInstalledFrameworks().FirstOrDefault(v => v >= runtimeVersion) is not Version installedRuntimeVer)
				throw new DirectoryNotFoundException($"Could not find installed Microsoft.NETCore.App runtime with version >= {runtimeVersion:3}");

			if (GetHosthostfxrPath(installedRuntimeVer) is not string hostPath)
				throw new FileNotFoundException($"Could not find the {PLATFORM} hostfxr.dll for runtime version {runtimeVersion:3}");

			if (target.LoadLibrary(hostPath) is not ProcessModule hostMod)
				throw new DllNotFoundException("Failed to load hostfxr.dll in the target process");

			var k3dMod = target.GetKernel32();

			var param = new InjectParams
			{
				fnConfig = hostMod.GetProcAddress("hostfxr_initialize_for_runtime_config"),
				fnGetDelegate = hostMod.GetProcAddress("hostfxr_get_runtime_delegate"),
				fnClose = hostMod.GetProcAddress("hostfxr_close"),
				fnVirtualFree = k3dMod.GetProcAddress("VirtualFree"),
				fnExitThread = k3dMod.GetProcAddress("ExitThread"),
				str_runtimeconfig = target.WriteMemory(runtimeconfig),
				str_dll_path = target.WriteMemory(dllToInject),
				str_method_name = target.WriteMemory(method),
				str_type = target.WriteMemory(asssemblyQualifiedTypeName),
				args = target.WriteMemory(argument),
				sz_args = argument.Length
			};

			var loader = target.WriteMemory(DOTNET_LOADER_ASM, MemoryProtection.Execute);

			return target.Call(loader, param, waitForReturn);
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
}
