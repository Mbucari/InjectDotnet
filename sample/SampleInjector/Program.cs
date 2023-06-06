using InjectDotnet;
using System.Diagnostics;

namespace SampleInjector;

struct Argument
{
	public IntPtr Title;
	public IntPtr Text;
	public IntPtr Picture;
	public int pic_sz;
}

internal unsafe class Program
{
	static void Main(string[] args)
	{
		//Change the process names to your targets. I used Win64's notepad for 64-bit testing and HxD hex editor for 32-bit testing.
		//Be sure to set the target paths in SampleInjected/Properties/launchSettings.json
		var proc = Environment.Is64BitProcess? Process.GetProcessesByName("notepad"): Process.GetProcessesByName("HxD32");

		var target = proc[^1];

		var picBytes = File.ReadAllBytes("dotnet.png");

		//Arguments to pass to SampleInjected
		//SampleInjected is responsible from loading this struct from unmanaged
		//memory and for freeing all memory allocated for the strings.
		var arg = new Argument
		{
			Title = target.WriteMemory("Injected Form"),
			Text = target.WriteMemory($"This form has been injected into {target.ProcessName} and is running in its memory space"),
			Picture = target.WriteMemory(picBytes),
			pic_sz = picBytes.Length
		};

		var fff = Injector.Inject(
			target,
			Path.GetFullPath("SampleInjected.runtimeconfig.json"),
			Path.GetFullPath("SampleInjected.dll"),
			"SampleInjected.Program, SampleInjected, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
			"Bootstrap",
			arg,
			waitForReturn: false);
	}
}