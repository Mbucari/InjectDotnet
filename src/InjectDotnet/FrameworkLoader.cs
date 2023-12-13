using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;

namespace InjectDotnet;

internal class FrameworkLoader : IManagedLoader
{
	public nint Loader { get; private init; }
	public nint Parameter { get; private init; }

	public static FrameworkLoader Create(Process target, string dllToInject, string typeName, string methodName, string methodArgument, bool entryPoint)
	{
		const string MSCOREE_DLL = "mscoree.dll";
		if (!File.Exists(dllToInject))
			throw new ArgumentException($"{nameof(dllToInject)} file not found");

		dllToInject = Path.GetFullPath(dllToInject);

		var mscoreePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), MSCOREE_DLL);

		if (!File.Exists(mscoreePath))
			throw new FileNotFoundException($"{MSCOREE_DLL} not found");

		string runtime;
		if (target.MainModule?.FileName is string targetExe && target.GetModulesByName(MSCOREE_DLL).Any())
		{
			//Target is a .NET Framework process. Match loaded runtime to existing runtime version.

			if (entryPoint)
				throw new ArgumentException("Cannot inject into a .NET Framework target at startup.", nameof(entryPoint));

			var (targetRuntime, targetVersion) = GetFileRuntimeVersion(targetExe);
			var (injectorRuntime, injectedVersion) = GetFileRuntimeVersion(dllToInject);

			if (injectedVersion > targetVersion)
				throw new Exception($"Injected Dll's framework version {injectorRuntime} is greater than the target's version {targetRuntime}");

			runtime = targetRuntime;
		}
		else
			(runtime, _) = GetFileRuntimeVersion(dllToInject);

		var k3dMod = target.GetKernel32();

		FrameworkParameters? param = null;
		nint? pLoader = null;
		nint? pParams = null;
		try
		{
			param = new FrameworkParameters(k3dMod)
			{
				fnEntryPoint = entryPoint ? target.MainModule?.EntryPointAddress ?? IntPtr.Zero : 0,
				str_CLRCreateInstance_name = target.WriteMemory(Encoding.ASCII.GetBytes("CLRCreateInstance")),
				str_runtime_version = target.WriteMemory(runtime),
				str_dll_path = target.WriteMemory(dllToInject),
				str_type = target.WriteMemory(typeName),
				str_method_name = target.WriteMemory(methodName),
				str_mscoree_path = target.WriteMemory(mscoreePath),
				str_argument = target.WriteMemory(methodArgument)
			};

			pLoader = target.WriteMemory(DOTNETFRAMEWORK_LOADER_ASM, Native.MemoryProtection.Execute);
			pParams = target.WriteMemory(param.Value);
			return new FrameworkLoader { Loader = pLoader.Value, Parameter = pParams.Value };
		}
		catch
		{
			if (param is FrameworkParameters p)
			{
				target.Free(p.str_CLRCreateInstance_name);
				target.Free(p.str_dll_path);
				target.Free(p.str_method_name);
				target.Free(p.str_type);
				target.Free(p.str_mscoree_path);
				target.Free(p.str_argument);
				target.Free(p.str_runtime_version);
			}
			if (pLoader.HasValue)
				target.Free(pLoader.Value);
			if (pParams.HasValue)
				target.Free(pParams.Value);
			throw;
		}
	}

	private static (string, Version) GetFileRuntimeVersion(string dllToInject)
	{
		using var fs = File.Open(dllToInject, FileMode.Open, FileAccess.Read, FileShare.Read);
		using var peReader = new PEReader(fs);
		var mr = peReader.GetMetadataReader();

		if (!Version.TryParse(mr.MetadataVersion?.Replace("v", ""), out var metadataVersion))
			throw new InvalidDataException($"Unable to parse metadata version \"{mr.MetadataVersion}\"");

		var frameworks = Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.Windows),
			"Microsoft.NET",
			Environment.Is64BitProcess ? "Framework64" : "Framework");

		foreach (var d in Directory.EnumerateDirectories(frameworks, "v*", SearchOption.TopDirectoryOnly))
		{
			var dirName = Path.GetFileName(d);
			if (Version.TryParse(dirName.AsSpan(1), out var v) && v >= metadataVersion)
				return (dirName, v);
		}
		throw new DirectoryNotFoundException($"Could not find an installed runtime with version >= {metadataVersion}");
	}

	#region Loader Parameters
	[StructLayout(LayoutKind.Explicit)]
	internal struct FrameworkParameters
	{
		//Kernel32 Procs
		[FieldOffset(0x0)]
		readonly nint fnVirtualFree;
		[FieldOffset(0x8)]
		readonly nint fnLoadLibrary;
		[FieldOffset(0x10)]
		readonly nint fnGetProcAddress;
		[FieldOffset(0x18)]
		public nint fnEntryPoint;
		[FieldOffset(0x20)]
		readonly nint fnExitThread;

		//CLR Instances
		[FieldOffset(0x28)]
		readonly nint pMetaHost;
		[FieldOffset(0x30)]
		readonly nint pRuntimeInfo;
		[FieldOffset(0x38)]
		readonly nint pClrRuntimeHost;

		//CLR Parameters
		[FieldOffset(0x40)]
		public nint str_mscoree_path;
		[FieldOffset(0x48)]
		public nint str_CLRCreateInstance_name;
		[FieldOffset(0x50)]
		public nint str_runtime_version;
		[FieldOffset(0x58)]
		public nint str_dll_path;
		[FieldOffset(0x60)]
		public nint str_type;
		[FieldOffset(0x68)]
		public nint str_method_name;
		[FieldOffset(0x70)]
		public nint str_argument;
		[FieldOffset(0x78)]
		readonly uint dw_return_value;

		[FieldOffset(0xb0)]
		readonly Guid _CLSID_CLRMetaHost;
		[FieldOffset(0xc0)]
		readonly Guid _IID_ICLRMetaHost;
		[FieldOffset(0xD0)]
		readonly Guid _IID_ICLRRuntimeInfo;
		[FieldOffset(0xE0)]
		readonly Guid _CLSID_CLRRuntimeHost;
		[FieldOffset(0xF0)]
		readonly Guid _IID_ICLRRuntimeHost;

		private static readonly Guid CLSID_CLRMetaHost = new(0x9280188d, 0x0e8e, 0x4867, 0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde);
		private static readonly Guid IID_ICLRMetaHost = new(0xd332db9e, 0xb9b3, 0x4125, 0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16);
		private static readonly Guid IID_ICLRRuntimeInfo = new(0xbd39d1d2, 0xba2f, 0x486a, 0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91);
		private static readonly Guid CLSID_CLRRuntimeHost = new(0x90f1a06e, 0x7712, 0x4762, 0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02);
		private static readonly Guid IID_ICLRRuntimeHost = new(0x90f1a06c, 0x7712, 0x4762, 0x86, 0xb5, 0x7a, 0x5e, 0xba, 0x6b, 0xdb, 0x02);

		public FrameworkParameters(ProcessModule k3dMod) : this()
		{
			_CLSID_CLRMetaHost = CLSID_CLRMetaHost;
			_IID_ICLRMetaHost = IID_ICLRMetaHost;
			_IID_ICLRRuntimeInfo = IID_ICLRRuntimeInfo;
			_CLSID_CLRRuntimeHost = CLSID_CLRRuntimeHost;
			_IID_ICLRRuntimeHost = IID_ICLRRuntimeHost;

			fnVirtualFree = k3dMod.GetProcAddress("VirtualFree");
			fnLoadLibrary = k3dMod.GetProcAddress("LoadLibraryW");
			fnGetProcAddress = k3dMod.GetProcAddress("GetProcAddress");
			fnExitThread = k3dMod.GetProcAddress("ExitThread");
		}
	}
	#endregion

	#region Loader
#if X64
	private static readonly byte[] DOTNETFRAMEWORK_LOADER_ASM = new byte[]
	{
		0x48, 0x83, 0xEC, 0x38,						//sub rsp, 0x38
		0x48, 0x89, 0xCD,							//mov rbp, rcx | Store InjectParams 1 in rbp
		0x48, 0x8B, 0x4D, 0x40,						//mov rcx, [str_mscoree_path]
		0xFF, 0x55, 0x08,							//call [fnLoadLibrary]
		0x48, 0x89, 0xC1,							//mov rcx, rax
		0x48, 0x8B, 0x55, 0x48,						//mov rdx, [str_CLRCreateInstance_name]
		0xFF, 0x55, 0x10,							//call [fnGetProcAddress]
		0x48, 0x8D, 0x8D, 0xB0, 0x00, 0x00, 0x00,	//lea rcx, [CLSID_CLRMetaHost]
		0x48, 0x8D, 0x95, 0xC0, 0x00, 0x00, 0x00,	//lea rcx, [IID_ICLRMetaHost]
		0x4C, 0x8D, 0x45, 0x28,						//lea r8, [pMetaHost]
		0xFF, 0xD0,									//call CLRCreateInstance
		0x85, 0xC0,									//test eax, eax
		0x74, 0x05,									//je ...
		0x89, 0xC1,									//mov ecx, eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x48, 0x8B, 0x4D, 0x28,						//mov rcx, [pMetaHost]
		0x48, 0x8B, 0x55, 0x50,						//mov rdx, [str_runtime_version]
		0x4C, 0x8D, 0x85, 0xD0, 0x00, 0x00, 0x00,	//lea r8, [IID_ICLRRuntimeInfo]
		0x4C, 0x8D, 0x4D, 0x30,						//lea r9, [pRuntimeInfo]
		0x48, 0x8B, 0x01,							//mov rax, [[pMetaHost]]
		0xFF, 0x50, 0x18,							//call [rax + 0x18] //	pMetaHost->GetRuntime()
		0x85, 0xC0,									//test eax, eax
		0x74, 0x05,									//je ...
		0x89, 0xC1,									//mov ecx, eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x48, 0x8B, 0x4D, 0x30,						//mov rcx, [pRuntimeInfo]
		0x48, 0x8D, 0x95, 0xE0, 0x00, 0x00, 0x00,	//lea rdx, [CLSID_CLRRuntimeHost]
		0x4C, 0x8D, 0x85, 0xF0, 0x00, 0x00, 0x00,	//lea r8, [IID_ICLRRuntimeHost]
		0x4C, 0x8D, 0x4D, 0x38,						//lea r9, [pClrRuntimeHost]
		0x48, 0x8B, 0x01,							//mov rax, [[pRuntimeInfo]]
		0xFF, 0x50, 0x48,							//call [rax + 0x48] //	pRuntimeInfo->GetInterface()
		0x85, 0xC0,									//test eax, eax
		0x74, 0x05,									//je ...
		0x89, 0xC1,									//mov ecx, eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x48, 0x8B, 0x4D, 0x38,						//mov rcx, [pClrRuntimeHost]
		0x48, 0x8B, 0x01,							//mov rax, [[pClrRuntimeHost]]
		0xFF, 0x50, 0x18,							//call [rax + 0x18] // pClrRuntimeHost->Start()
		0x85, 0xC0,									//test eax, eax
		0x74, 0x0A,									//je ...
		0x83, 0xF8, 0x01,							//cmp eax,1
		0x74, 0x05,									//je ...
		0x89, 0xC1,									//mov ecx, eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x48, 0x8B, 0x4D, 0x38,						//mov rcx, [pClrRuntimeHost]
		0x48, 0x8B, 0x55, 0x58,						//mov rdx, [str_dll_path]
		0x4C, 0x8B, 0x45, 0x60,						//mov r8, [str_type]
		0x4C, 0x8B, 0x4D, 0x68,						//mov r9, [str_method_name]
		0x48, 0x8B, 0x45, 0x70,						//mov rax, [str_argument]
		0x48, 0x89, 0x44, 0x24, 0x20,				//mov [rsp + 0x20], rax
		0x48, 0x8D, 0x45, 0x78,						//lea rax, [dw_return_value]
		0x48, 0x89, 0x44, 0x24, 0x28,				//mov [rsp + 0x28], rax
		0x48, 0x8B, 0x01,							//mov rax, [[pClrRuntimeHost]]
		0xFF, 0x50, 0x58,							//call [rax + 0x58] // pClrRuntimeHost->ExecuteInDefaultAppDomain()
		0x85, 0xC0,									//test eax, eax
		0x74, 0x05,									//je ...
		0x89, 0xC1,									//mov ecx, eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x48, 0x8B, 0x4D, 0x28,						//mov rcx, [pMetaHost]
		0x48, 0x8B, 0x01,							//mov rax, [[pMetaHost]]
		0xFF, 0x50, 0x10,							//call [rax + 0x10] // pMetaHost->Release()
		0x48, 0x8B, 0x4D, 0x30,						//mov rcx, [pRuntimeInfo]
		0x48, 0x8B, 0x01,							//mov rax, [[pRuntimeInfo]]
		0xFF, 0x50, 0x10,							//call [rax + 0x10] // pRuntimeInfo->Release()
		0x48, 0x8B, 0x4D, 0x38,						//mov rcx, [pClrRuntimeHost]
		0x48, 0x8B, 0x01,							//mov rax, [[pClrRuntimeHost]]
		0xFF, 0x50, 0x10,							//call [rax + 0x10] // pClrRuntimeHost->Release()
		0x8B, 0x7D, 0x78,							//mov rdi, [dw_return_value]
		0x48, 0x31, 0xDB,							//xor rbx,rbx
		0xB3, 0x07,									//mov bl,7
		//FREELOOP:
		0xFE, 0xCB,									//dec bl
		0x48, 0x8B, 0x4C, 0xDD, 0x40,				//mov rcx, [rbp + rbx * 8 + 0x40]
		0x48, 0x31, 0xD2,							//xor rdx, rdx
		0x49, 0xC7, 0xC0, 0x00, 0x80, 0x00, 0x00,	//mov r8, MEM_RELEASE
		0xFF, 0x55, 0x00,							//call [fnVirtualFree]
		0x84, 0xDB,									//test bl, bl
		0x75, 0xE8,									//jne FREELOOP
		0x48, 0x8B, 0x75, 0x18,						//mov rsi, [fnEntryPoint]
		0x48, 0x89, 0xE9,							//mov rcx, (Arg)
		0x48, 0x31, 0xD2,							//xor rdx, rdx
		0x41, 0xB8, 0x00, 0x80, 0, 0,				//mov r8d, MEM_RELEASE
		0xFF, 0x55, 0x0,							//call [Arg.fnVirtualFree]
		0x8B, 0xC7,									//mov eax, edi
		0x48, 0x83, 0xC4, 0x38,						//add rsp, 0x38
		0x48, 0x85, 0xF6,							//test rsi,rsi
		0x74, 0x02,									//je RETURN
		0xFF, 0xE6,									//jmp [EntryPoint]
		0xC3										//ret
	};
#elif X86

	private static readonly byte[] DOTNETFRAMEWORK_LOADER_ASM = new byte[]
	{
		0x8B, 0x6C, 0x24, 0x04,						//mov ebp, [esp+0x4] // Store InjectParams in rbp
		0xFF, 0x75, 0x40,							//push [str_mscoree_path]
		0xFF, 0x55, 0x08,							//call [fnLoadLibrary]
		0xFF, 0x75, 0x48,							//push [str_CLRCreateInstance_name]
		0x50,										//push eax
		0xFF, 0x55, 0x10,							//call [fnGetProcAddress]
		0x8D, 0x5D, 0x28,							//lea ebx, [pMetaHost]
		0x53,										//push ebx
		0x8D, 0x9D, 0xC0, 0x00, 0x00, 0x00,			//lea [IID_ICLRMetaHost]
		0x53,										//push ebx
		0x8D, 0x9D, 0xB0, 0x00, 0x00, 0x00,			//lea [CLSID_CLRMetaHost]
		0x53,										//push ebx
		0xFF, 0xD0,									//call CLRCreateInstance
		0x85, 0xC0,									//test eax, eax
		0x74, 0x04,									//je ...
		0x50,										//push eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x8D, 0x5D, 0x30,							//lea ebx, [pRuntimeInfo]
		0x53,										//push ebx
		0x8D, 0x9D, 0xD0, 0x00, 0x00, 0x00,			//lea ebx, [IID_ICLRRuntimeInfo]
		0x53,										//push ebx
		0xFF, 0x75, 0x50,							//push [str_runtime_version]
		0x8B, 0x45, 0x28,							//mov eax, [pMetaHost]
		0x50,										//push eax
		0x8B, 0x00,									//mov eax, [[pMetaHost]]
		0xFF, 0x50, 0x0C,							//call [eax + 0xC] //	pMetaHost->GetRuntime()
		0x85, 0xC0,									//test eax, eax
		0x74, 0x04,									//je ...
		0x50,										//push eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x8D, 0x45, 0x38,							//lea eax, [pClrRuntimeHost]
		0x50,										//push eax
		0x8D, 0x85, 0xF0, 0x00, 0x00, 0x00,			//lea eax, [IID_ICLRRuntimeHost]
		0x50,										//push eax
		0x8D, 0x85, 0xE0, 0x00, 0x00, 0x00,			//lea rdx, [CLSID_CLRRuntimeHost]
		0x50,										//push eax
		0x8B, 0x45, 0x30,							//mov eax, [pRuntimeInfo]
		0x50,										//push eax
		0x8B, 0x00,									//mov eax, [[pRuntimeInfo]]
		0xFF, 0x50, 0x24,							//call [eax + 0x24] //	pRuntimeInfo->GetInterface()
		0x85, 0xC0,									//test eax, eax
		0x74, 0x04,									//je ...
		0x50,										//push eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x8B, 0x45, 0x38,							//mov eax, [pClrRuntimeHost]
		0x50,										//push eax
		0x8B, 0x00,									//mov eax, [[pClrRuntimeHost]]
		0xFF, 0x50, 0x0C,							//call [eax + 0xC] // pClrRuntimeHost->Start()
		0x85, 0xC0,									//test eax, eax
		0x74, 0x09,									//je ...
		0x83, 0xF8,	0x01,							//cmp eax,1
		0x74, 0x04,									//je ...
		0x50,										//push eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x8D, 0x45, 0x78,							//lea eax, [dw_return_value]
		0x50,										//push eax
		0xFF, 0x75, 0x70,							//push [str_argument]
		0xFF, 0x75, 0x68,							//push [str_method_name]
		0xFF, 0x75, 0x60,							//push [str_type]
		0xFF, 0x75, 0x58,							//push [str_dll_path]
		0x8B, 0x45, 0x38,							//mov eax, [pClrRuntimeHost]
		0x50,										//push eax
		0x8B, 0x00,									//mov eax, [[pClrRuntimeHost]]
		0xFF, 0x50, 0x2c,							//call [eax + 0x2c] // pClrRuntimeHost->ExecuteInDefaultAppDomain()
		0x85, 0xC0,									//test eax, eax
		0x74, 0x04,									//je ...
		0x50,										//push eax
		0xFF, 0x55, 0x20,							//call [ExitThread]
		0x8B, 0x45, 0x28,							//mov eax, [pMetaHost]
		0x50,										//push eax
		0x8B, 0x00,									//mov eax, [[pMetaHost]]
		0xFF, 0x50, 0x08,							//call [eax + 0x8] // pMetaHost->Release()
		0x8B, 0x45, 0x30,							//mov eax, [pRuntimeInfo]
		0x50,										//push eax
		0x8B, 0x00,									//mov eax, [[pRuntimeInfo]]
		0xFF, 0x50, 0x08,							//call [eax + 0x8] // pRuntimeInfo->Release()
		0x8B, 0x45, 0x38,							//mov eax, [pClrRuntimeHost]
		0x50,										//push eax
		0x8B, 0x00,									//mov eax, [[pClrRuntimeHost]]
		0xFF, 0x50, 0x08,							//call [eax + 0x8] // pClrRuntimeHost->Release()
		0x8B, 0x7D, 0x78,							//mov edi, [dw_return_value]
		0x31, 0xDB,									//xor ebx,ebx
		0xB3, 0x07,									//mov bl,7
		//FREELOOP:
		0xFE, 0xCB,									//dec bl
		0x68, 0x00, 0x80, 0x00, 0x00,				//push MEM_RELEASE
		0x6A, 0x00,									//push 0
		0xFF, 0x74, 0xDD, 0x40,						//push [ebp + ebx * 8 + 0x40]
		0xFF, 0x55, 0x00,							//call [fnVirtualFree]
		0x84, 0xDB,									//test bl, bl
		0x75, 0xEC,									//jne FREELOOP
		0x8B, 0x75, 0x18,							//mov esi, [fnEntryPoint]
		0x68, 0x00, 0x80, 0x00, 0x00,				//push MEM_RELEASE
		0x6A, 0x00,									//push 0
		0x55,										//push ebp
		0xFF, 0x55, 0x0,							//call [fnVirtualFree]
		0x8B, 0xC7,									//mov eax, edi
		0x85, 0xF6,									//test esi,esi
		0x74, 0x02,									//je RETURN
		0xFF, 0xE6,									//jmp [EntryPoint]
		0xC3										//ret
	};
#endif
	#endregion
}
