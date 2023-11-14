using InjectDotnet;
using InjectDotnet.Debug;

/*
 * This example creates a new process and debugs it.
 * 
 * InjectedDll is injected by the debugger at the debugee's
 * entry point, and the original entry point is executed after
 * InjectedDll.HookDemo.Bootstrap() returns.
 */

namespace InjectAtStartup;

struct Argument
{
	public IntPtr Title;
	public IntPtr Text;
	public IntPtr Picture;
	public int pic_sz;
}

internal class Program
{
	static readonly string Bitness = Environment.Is64BitProcess ? "64" : "32";
	static readonly string Target = $@"..\..\..\Targets\HxD{Bitness}.exe";

	static async Task Main()
	{
		var debugger = new Debugger(Target, arguments: null);
		var picBytes = File.ReadAllBytes("dotnet.png");

		var arg = new Argument
		{
			Title = debugger.WriteMemory("Injected Form"),
			Text = debugger.WriteMemory($"This form has been injected into {debugger.ImagePath} and is running in its memory space"),
			Picture = debugger.WriteMemory(picBytes),
			pic_sz = picBytes.Length
		};

		//Injection must occur before calling ResumeProcessAsync()
		debugger.InjectStartup(
			"InjectedDll.runtimeconfig.json",
			"InjectedDll.dll",
			"InjectedDll.HookDemo, InjectedDll, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
			"Bootstrap",
			arg,
			detatchAfterInjected: false);
		//NOTE: By not detatching after injecting, the Hardware breakpoint hook
		//will be caught by the debugger. For it to work we need to not handle
		//the single step event that occurs at kernel32.WriteFile.

		debugger.OutputDebugString += Debugger_OutputDebugString;
		debugger.ExitProcess += Debugger_ExitProcess;
		debugger.SingleStep += Debugger_SingleStep;
		debugger.LoadDll += Debugger_LoadDll;

		await debugger.ResumeProcessAsync();
	}

	private static void Debugger_LoadDll(object? sender, LoadDllEventArgs e)
	{
		if (e.ModuleName.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase) is true)
		{
			//Get the address of kernel32.WriteFile.
			using var proc = e.GetProcess();
			if (ProcessExtensions.GetExportOffset("kernel32.dll", "WriteFile") is nint offset)
				Address = e.BaseOfDll + offset;
		}
	}

	static nint Address;

	private static void Debugger_SingleStep(object? sender, SingleStepEventArgs e)
	{
		//Don't handle the hardware breakpoint at kernel32.WriteFile.
		e.Handled = e.Address != Address;
	}

	private static void Debugger_ExitProcess(object? sender, ExitProcessEventArgs e)
	{
		Console.WriteLine($"Process exited with code 0x{e.ExitCode:x}");
	}

	private static void Debugger_OutputDebugString(object? sender, OutputDebugStringEventArgs e)
	{
		Console.WriteLine(e.DebugString);
	}
}