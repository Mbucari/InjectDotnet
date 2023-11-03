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
	public bool CreateForm;
}

internal class Program
{
	static readonly string Bitness = Environment.Is64BitProcess ? "64" : "32";
	static readonly string Target = $@"..\..\..\Targets\HxD{Bitness}.exe";

	static async Task Main()
	{
		var exists = File.Exists(Target);
		var debugger = new Debugger(Target, arguments: null);
		var picBytes = File.ReadAllBytes("dotnet.png");

		var arg = new Argument
		{
			Title = debugger.WriteMemory("Injected Form"),
			Text = debugger.WriteMemory($"This form has been injected into {debugger.ImagePath} and is running in its memory space"),
			Picture = debugger.WriteMemory(picBytes),
			pic_sz = picBytes.Length,
			CreateForm = false //Because we're injecting at startup, the Bootstrap method must return before the program can continue
		};

		//Injection must occur before calling ResumeProcessAsync()
		debugger.InjectStartup(
			"InjectedDll.runtimeconfig.json",
			"InjectedDll.dll",
			"InjectedDll.HookDemo, InjectedDll, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
			"Bootstrap",
			arg,
			detatchAfterInjected: false);

		debugger.OutputDebugString += Debugger_OutputDebugString;
		debugger.ExitProcess += Debugger_ExitProcess;

		await debugger.ResumeProcessAsync();
	}

	private static void Debugger_ExitProcess(object? sender, ExitProcessEventArgs e)
	{
		Console.WriteLine($"Process exited with code {e.ExitCode}");
	}

	private static void Debugger_OutputDebugString(object? sender, OutputDebugStringEventArgs e)
	{
		Console.WriteLine(e.DebugString);
	}
}