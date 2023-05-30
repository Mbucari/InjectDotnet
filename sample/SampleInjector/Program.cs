using InjectDotnet;
using System.Diagnostics;

namespace SampleInjector
{
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
			var notepads = Process.GetProcessesByName("notepad");

			var target = notepads.Length == 0 ? Process.Start("notepad.exe") : notepads[0];

			var picFile = @"..\..\..\SampleInjector\dotnet.png";
			var picBytes = File.ReadAllBytes(picFile);

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

			Injector.Inject(
				target,
				Path.GetFullPath("SampleInjected.runtimeconfig.json"),
				Path.GetFullPath("SampleInjected.dll"),
				"SampleInjected.Program, SampleInjected, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
				"Bootstrap",
				arg,
				waitForReturn: false);
		}
	}
}