using InjectDotnet;
using InjectDotnet.Debug;
using System.Diagnostics;

/*
 * This example injects InjectedDll into an active process.
 * 
 * The injector creates a new thread in the target and executes
 * InjectedDll.HookDemo.Bootstrap().
 */

namespace InjectIntoRunning;

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

	static void Main()
	{
		var targetName = Path.GetFileNameWithoutExtension(Target);
		var targetFullPath = Path.GetFullPath(Target);

		var target
			= Process
			.GetProcesses()
			.Where(p => string.Equals(p.ProcessName, targetName, StringComparison.OrdinalIgnoreCase))
			.FirstOrDefault(p => string.Equals(p.MainModule?.FileName, targetFullPath, StringComparison.OrdinalIgnoreCase));

		if (target is null)
		{
			Console.Error.WriteLine($"Could not find running process for {Target}");
			return;
		}

		var picBytes = File.ReadAllBytes("dotnet.png");
		var arg = new Argument
		{
			Title = target.WriteMemory("Injected Form"),
			Text = target.WriteMemory($"This form has been injected into {target.MainModule?.FileName} and is running in its memory space"),
			Picture = target.WriteMemory(picBytes),
			pic_sz = picBytes.Length,
			CreateForm = true
		};

		var result = target.Inject(
			"InjectedDll.runtimeconfig.json",
			"InjectedDll.dll",
			"InjectedDll.HookDemo, InjectedDll, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
			"Bootstrap",
			arg,
			waitForReturn: true);

		Console.WriteLine($"InjectedDll.HookDemo.Bootstrap() returned 0x{result:x}");
	}
}