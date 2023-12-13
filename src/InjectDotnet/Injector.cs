using InjectDotnet.Debug;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace InjectDotnet;

#pragma warning disable CS9191 // The 'ref' modifier for an argument corresponding to 'in' parameter is equivalent to 'in'. Consider using 'in' instead.
public static class Injector
{
	/// <summary>
	/// Inject a .NET dll into an Win32 or Win64 native target process.
	/// </summary>
	/// <typeparam name="T">Struct type to be passed to the injected dll</typeparam>
	/// <param name="target">The target into which the dotnet dll will be injected</param>
	/// <param name="runtimeconfig">Path to the .runtimeconfig.json file for the dll to be injected</param>
	/// <param name="dllToInject">Path to the .NET dll to be injected</param>
	/// <param name="asssemblyQualifiedTypeName">Full <see cref="Type.AssemblyQualifiedName"/> type name</param>
	/// <param name="method">Name of the static method in the injected dll to be invoked upon injection. Must have signature <see cref="int"/>(<see cref="IntPtr"/>, <see cref="int"/>)</param>
	/// <param name="methodArgument">Argument to be passed to the method. All reference types must be written to the <paramref name="target"/> target's memory, and the dll must free that memory.</param>
	/// <param name="waitForReturn">Whether to wait for <paramref name="method"/> to return</param>
	/// <returns>If <paramref name="waitForReturn"/> is true, the value returned by <paramref name="method"/>. Otherwise null.</returns>
	public static int? Inject<T>(this Process target, string runtimeconfig, string dllToInject, string asssemblyQualifiedTypeName, string method, T methodArgument, bool waitForReturn = true)
		where T : struct
	{
		var size = Marshal.SizeOf<T>();
		Span<byte> argBts = new byte[size];
		MemoryMarshal.Write(argBts, ref methodArgument);
		return Inject(target, runtimeconfig, dllToInject, asssemblyQualifiedTypeName, method, argBts, waitForReturn);
	}

	/// <summary>
	/// Inject a .NET dll into an Win32 or Win64 native target process at the entry point. The injected method will execute before the entry point.
	/// </summary>
	/// <typeparam name="T">Struct type to be passed to the injected dll</typeparam>
	/// <param name="debugger">The debugger into which the dotnet dll will be injected. Debugee must not have already executed the entry point.</param>
	/// <param name="runtimeconfig">Path to the .runtimeconfig.json file for the dll to be injected</param>
	/// <param name="dllToInject">Path to the .NET dll to be injected</param>
	/// <param name="asssemblyQualifiedTypeName">Full <see cref="Type.AssemblyQualifiedName"/> type name</param>
	/// <param name="method">Name of the static method in the injected dll to be invoked upon injection. Must have signature <see cref="int"/>(<see cref="IntPtr"/>, <see cref="int"/>)</param>
	/// <param name="methodArgument">Argument to be passed to the method. All reference types must be written to the <paramref name="debugger"/> target's memory, and the dll must free that memory.</param>
	public static void InjectStartup<T>(this Debug.Debugger debugger, string runtimeconfig, string dllToInject, string asssemblyQualifiedTypeName, string method, T methodArgument, bool detatchAfterInjected = true)
		where T : struct
	{
		if (debugger.HasHitEntryPoint)
			throw new InvalidOperationException("Cannot inject after execution has passed the debugee's entry point.");

		debugger.Breakpoint += (s, e) =>
		{
			if (e.Type is BreakType.EntryPoint)
			{
				using var process = Process.GetProcessById(debugger.ProcessInfo.ProcessId);
				var size = Marshal.SizeOf<T>();
				Span<byte> argBts = new byte[size];
				MemoryMarshal.Write(argBts, ref methodArgument);

				var loader = CoreLoader.Create(process, runtimeconfig, dllToInject, asssemblyQualifiedTypeName, method, argBts, true);
				e.Context.InstructionPointer = loader.Loader;
#if X64
				e.Context.Rcx = loader.Parameter;
#elif X86

				var esp = e.Context.StackPointer;
				debugger.MemoryAccess.WriteMemory(esp + 4, BitConverter.GetBytes(loader.Parameter));
#endif
				e.Continue = !detatchAfterInjected;
				return;
			}
			e.Continue = true;
		};
	}

	/// <summary>
	/// Inject a .NET dll into an Win32 or Win64 native target process.
	/// </summary>
	/// <param name="target">The process into which the dotnet dll will be injected</param>
	/// <param name="runtimeconfig">Path to the .runtimeconfig.json file for the dll to be injected</param>
	/// <param name="dllToInject">Path to the .NET dll to be injected</param>
	/// <param name="asssemblyQualifiedTypeName">Full <see cref="Type.AssemblyQualifiedName"/> type name</param>
	/// <param name="method">Name of the static method in the injected dll to be invoked upon injection. Must have signature <see cref="int"/>(<see cref="IntPtr"/>, <see cref="int"/>)</param>
	/// <param name="argument">Argument to be passed to the method</param>
	/// <param name="waitForReturn">Whether to wait for <paramref name="method"/> to return</param>
	/// <returns>If <paramref name="waitForReturn"/> is true, the value returned by <paramref name="method"/>. Otherwise null.</returns>
	public static int? Inject(this Process target, string runtimeconfig, string dllToInject, string asssemblyQualifiedTypeName, string method, string argument, bool waitForReturn = true)
	{
		var argBts = MemoryMarshal.AsBytes(argument.AsSpan());
		return Inject(target, runtimeconfig, dllToInject, asssemblyQualifiedTypeName, method, argBts, waitForReturn);
	}

	/// <summary>
	/// Inject a .NET dll into an Win32 or Win64 native target process at the entry point. The injected method will execute before the entry point.
	/// </summary>
	/// <param name="debugger">The debugger into which the dotnet dll will be injected. Debugee must not have already executed the entry point.</param>
	/// <param name="runtimeconfig">Path to the .runtimeconfig.json file for the dll to be injected</param>
	/// <param name="dllToInject">Path to the .NET dll to be injected</param>
	/// <param name="asssemblyQualifiedTypeName">Full <see cref="Type.AssemblyQualifiedName"/> type name</param>
	/// <param name="method">Name of the static method in the injected dll to be invoked upon injection. Must have signature <see cref="int"/>(<see cref="IntPtr"/>, <see cref="int"/>)</param>
	/// <param name="methodArgument">Argument to be passed to the method.</param>
	public static void InjectStartup(this Debug.Debugger debugger, string runtimeconfig, string dllToInject, string asssemblyQualifiedTypeName, string method, string methodArgument, bool detatchAfterInjected = true)
	{
		if (debugger.HasHitEntryPoint)
			throw new InvalidOperationException("Cannot inject after execution has passed the debugee's entry point.");

		debugger.Breakpoint += (s, e) =>
		{
			if (e.Type is BreakType.EntryPoint)
			{
				using var process = Process.GetProcessById(debugger.ProcessInfo.ProcessId);
				var argBts = MemoryMarshal.AsBytes(methodArgument.AsSpan());
				var loader = CoreLoader.Create(process, runtimeconfig, dllToInject, asssemblyQualifiedTypeName, method, argBts, true);
				e.Context.InstructionPointer = loader.Loader;

#if X64
				e.Context.Rcx = loader.Parameter;
#elif X86

				var esp = e.Context.StackPointer;
				debugger.MemoryAccess.WriteMemory(esp + 4, BitConverter.GetBytes(loader.Parameter));
#endif
				e.Continue = !detatchAfterInjected;
				return;
			}
			e.Continue = true;
		};
	}

	/// <summary>
	/// Inject a .NET Core dll into an Win32 or Win64 native target process.
	/// </summary>
	/// <param name="target">The process into which the dotnet dll will be injected</param>
	/// <param name="runtimeconfig">Path to the .runtimeconfig.json file for the dll to be injected</param>
	/// <param name="dllToInject">Path to the .NET dll to be injected</param>
	/// <param name="asssemblyQualifiedTypeName">Full <see cref="Type.AssemblyQualifiedName"/> type name</param>
	/// <param name="method">Name of the static method in the injected dll to be invoked upon injection. Must have signature <see cref="int"/>(<see cref="IntPtr"/>, <see cref="int"/>)</param>
	/// <param name="methodArgument">Argument to be passed to the method</param>
	/// <param name="waitForReturn">Whether to wait for <paramref name="method"/> to return</param>
	/// <returns>If <paramref name="waitForReturn"/> is true, the value returned by <paramref name="method"/>. Otherwise null.</returns>
	public static int? Inject(this Process target, string runtimeconfig, string dllToInject, string asssemblyQualifiedTypeName, string method, ReadOnlySpan<byte> methodArgument, bool waitForReturn = true)
	{
		var loader = CoreLoader.Create(target, runtimeconfig, dllToInject, asssemblyQualifiedTypeName, method, methodArgument, false);

		return target.Call(loader.Loader, loader.Parameter, waitForReturn);
	}

	/// <summary>
	/// Inject a .NET Framework dll into an Win32 or Win64 native target process.
	/// </summary>
	/// <param name="target">The process into which the dotnet dll will be injected</param>
	/// <param name="dotnetFrameworkDll">Path to the .NET Framework dll to be injected</param>
	/// <param name="typeName">The name of the <see cref="Type"/> that defines the method to invoke.</param>
	/// <param name="methodName">The name of the static method to invoke. Must have signature <see cref="int"/>(<see cref="string"/>)</param>
	/// <param name="methodArgument">The string parameter to pass to <paramref name="methodName"/>.</param>
	/// <param name="waitForReturn">Whether to wait for <paramref name="methodName"/> to return</param>
	/// <returns>If <paramref name="waitForReturn"/> is true, the value returned by <paramref name="methodName"/>. Otherwise null.</returns>
	public static int? Inject(this Process target, string dotnetFrameworkDll, string typeName, string methodName, string methodArgument, bool waitForReturn = true)
	{
		var loader = FrameworkLoader.Create(target, dotnetFrameworkDll, typeName, methodName, methodArgument, false);

		return target.Call(loader.Loader, loader.Parameter, waitForReturn);
	}

	/// <summary>
	/// Inject a .NET Framework dll into an Win32 or Win64 native target process at the entry point. The injected method will execute before the entry point.
	/// </summary>
	/// <typeparam name="T">Struct type to be passed to the injected dll</typeparam>
	/// <param name="debugger">The target into which the dotnet dll will be injected. Debugee must not have already executed the entry point.</param>
	/// <param name="dotnetFrameworkDll">Path to the .NET Framework dll to be injected</param>
	/// <param name="typeName">The name of the <see cref="Type"/> that defines the method to invoke.</param>
	/// <param name="methodName">The name of the static method to invoke. Must have signature <see cref="int"/>(<see cref="string"/>)</param>
	/// <param name="methodArgument">The string parameter to pass to <paramref name="methodName"/>.</param>
	public static void InjectStartup(this Debug.Debugger debugger, string dotnetFrameworkDll, string typeName, string methodName, string methodArgument, bool detatchAfterInjected = true)
	{
		if (debugger.HasHitEntryPoint)
			throw new InvalidOperationException("Cannot inject after execution has passed the debugee's entry point.");

		debugger.Breakpoint += (s, e) =>
		{
			if (e.Type is BreakType.EntryPoint)
			{
				using var process = Process.GetProcessById(debugger.ProcessInfo.ProcessId);

				var loader = FrameworkLoader.Create(process, dotnetFrameworkDll, typeName, methodName, methodArgument, true);
				e.Context.InstructionPointer = loader.Loader;
#if X64
				e.Context.Rcx = loader.Parameter;
#elif X86

				var esp = e.Context.StackPointer;
				debugger.MemoryAccess.WriteMemory(esp + 4, BitConverter.GetBytes(loader.Parameter));
#endif
				e.Continue = !detatchAfterInjected;
				return;
			}
			e.Continue = true;
		};
	}
}
