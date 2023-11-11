# InjectDotnet

Inject a .NET Core dll into a native Win32 or Win64 process. InjectDotnet is a library, not a standalone application. This allows developers/hackers to pass any argument to the injected dll, not just a string. There are two complementary libraries:

- **InjectDotnet**: Injects a managed dll into a native process.
- **InjectDotnet.NativeHelper**: Referenced by the injected dll and provides methods for hooking native functions.

Add [InjectDotnet](https://www.nuget.org/packages/InjectDotnet) to your injector, and add [InjectDotnet.NativeHelper](https://www.nuget.org/packages/InjectDotnet.NativeHelper) to your injected dll.

 **\*\*IMPORTANT\*\*  Your projects myst be configures x64 or x86, not AnyCPU!!**

## No Unmanaged Libraries

Unlike other dotnet dll injectors, this one does not rely on a native dll to load the runtime in the target process. Loading and executing the injected dll is accomplished by hand-written assembly instructions that are written directly into the target process' memory space and executed.

## Inject Into Running Processes

**InjectDotnet** Supports injecting managed Dlls into running processes using the traditional `CreateRemoteThread()` method.

It's as simple as the following example.

```C#
var target = Process.GetProcessesByName("target");

target.Inject(
	"InjectedDll.runtimeconfig.json",
	"InjectedDll.dll",
	"InjectedDll.HookDemo, InjectedDll, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
	"Bootstrap",
	"this is an argument passed to the injected dll's Bootstrap() method");
```

You may optionally wait for bootstrap method to return to receive it's return code, and the injector supports passing structs with additional data to the injected dll (see the samples prokjects).

## Inject Into a New Process at Startup

**InjectDotnet** Supports injecting managed Dlls at the entry point of a process using its built-in debugger.

It's as simple as the following example.

```C#
var debugger = new Debugger("target.exe", arguments: null);

debugger.InjectStartup(
	"InjectedDll.runtimeconfig.json",
	"InjectedDll.dll",
	"InjectedDll.HookDemo, InjectedDll, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null",
	"Bootstrap",
	"this is an argument passed to the injected dll's Bootstrap() method");

await debugger.ResumeProcessAsync();
```
The debugger supports all [win32 debug events](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-debug_event#members), and you may use them to, for example, receive data from the injected dll via [OutputDebugString](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-outputdebugstringw).

## Hooking Native Functions

**InjectDotnet.NativeHelper** supports three different hooking methods:

|Hook Type|Description|
|-|-|
|[ImportHook](docs/HookingImports.md)|Replaces the hooked function's import address table entry in the target module with a pointer to the hooking function.|
|[JumpHook](docs/HookingExports.md)|Overwrite's the first instruction(s) of the hooked function with a jump to a Trampoline.|
|[BreakpointHook](docs/BreakpointHooks.md)|Sets a hardware breakpoint at the hooked function's first instruction and uses a vectored exception handler to intercept execution.|

## See the samples for useage.
There are two sample projects:
- **InjectedDll** - A .NET 7.0 dll to be injected into a native process and uses `InjectDotnet.NativeHelper` to hook native functions.
- **InjectIntoRunning** - The program that uses `InjectDotnet` to inject `InjectedDll` into HxD.exe and pass it two strings and a png image as arguments. Executes `InjectedDll.HookDemo.Bootstrap` after injection.
- **InjectAtStartup** - The program that uses `InjectDotnet` to debug HxD.exe and inject `InjectedDll` at its entry point. Executes `InjectedDll.HookDemo.Bootstrap` after injection.

`SampleInjected.Program.Bootstrap` loads the two strings and the png image from native memory, frees the native memory, and then opens a `System.Windows.Forms.Form` to display the strings and image.

It also hooks the `WriteFile` function imported by notepad.exe from kernel32.dll and the `CreateFileW` function exported by kernel32.dll.

## Debugging Injected Dlls with Visual Studio

Ther are two ways to debug injected .NET dlls in Visual Studio

### Method 1: Set a Native Executable as the Debug Target
1. In Visual Studio, navigate to the injected dll's properties > Debug > Open debug launch profiles UI
2. Create a new "Executable" profile.
3. Enter the native executable into which this dll will be injected and any command line arguments. Save.
4. Choose the newly-created debug profile and launch the debugger.
5. Execute `SampleInjector.exe` to perform the injection

### Method 2: Attaching to Injected Process

1. Build  `SampleInjected` and `SampleInjector` targeting the platform of your Windows PC
2. Start the target native process (notepad.exe in the sample)
3. With the `SampleInjected` project open, attach the Visual Studio debugger the target process
    1. Debug > Attach to Process of `Ctrl+Alt+P`
    2. Select the .NET Core Debugger
        1. Next to "Attach to:", click "Select"
        2. Select "Debug these code types"
        3. Choose "Managed (.NET Core, .NET 5+)"
    3. Choose the target process. (easiest accomplished by clicking "Select Window" and clicking on the target's window)
    4. Click "Attach"
4. Execute `SampleInjector.exe` to perform the injection

