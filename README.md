# InjectDotnet

Inject a .NET Core dll into a native Win32 or Win64 process. InjectDotnet is a library, not a standalone application. This allows developers/hackers to pass any argument to the injected dll, not just a string. There are two complementary libraries:

- **InjectDotnet**: Injects a managed dll into a native process.
- **InjectDotnet.NativeHelper**: Referenced by the injected dll and provides methods for hooking native functions

Add [InjectDotnet](https://www.nuget.org/packages/InjectDotnet) to your injector, and add [InjectDotnet.NativeHelper](https://www.nuget.org/packages/InjectDotnet.NativeHelper) to your injected dll.

## No Unmanaged Libraries

Unlike other dotnet dll injectors, this one does not rely on a native dll to load the runtime in the target process. Loading and executing the injected dll is accomplished by hand-written assembly instructions that are written directly into the target process' memory space and executed.

## Hooking Imported Functions
Hooking imports is accomplished by replacing the target function's address in a module's import address table with a pointer to the hook delegate. The hook delegate can be either an `[UnmanagedCallersOnly]` method or a managed delegate with the same signature as the imported function. The original function pointer is stored in `ImportHook.OriginalFunction` and can be called by creating a delegate for it.

In the sample, all of notepad.exe's calls to `WriteFile` will call `WriteFile_hook`, and `WriteFile_hook` modifies the parameters before calling `Kernel32.WriteFile`.

```C#
static INativeHook? WriteFileHook;
static WriteFileDelegate? WriteFile_original;

delegate bool WriteFileDelegate(
    IntPtr hFile,
    byte* lpBuffer,
    int nNumberOfBytesToWrite,
    ref int lpNumberOfBytesWritten,
    IntPtr lpOverlapped);

public static int Bootstrap(IntPtr argument, int size)
{
    //Hook kernel32.WriteFile in the main module's import table
    WriteFileHook
        = Process
        .GetCurrentProcess()
        .MainModule
        ?.GetImportByName("kernel32", "WriteFile")
        ?.Hook(WriteFile_hook);

    if (WriteFileHook is not null)
        WriteFile_original = Marshal
        .GetDelegateForFunctionPointer<WriteFileDelegate>(WriteFileHook.OriginalFunction);
}

static bool WriteFile_hook(
    IntPtr hFile,
    byte* lpBuffer,
    int nNumberOfBytesToWrite,
    ref int NumberOfBytesWritten,
    IntPtr lpOverlapped)
{
    return  WriteFile_original!(hFile, lpBuffer, nNumberOfBytesToWrite, ref NumberOfBytesWritten, lpOverlapped);
}
```
## Hooking Exported Functions

Hooking exports is accomplished by overwriting the original function's entry point instructions with a jump to a block of memory allocated nearby. NativeHelper will attempt to create a trampoline (using a C# port of [minhook](https://github.com/TsudaKageyu/minhook)). If successdul, the original function may be called without removing the hook. If trampoline creation failed, the hook must be removed via `RemoveHook()` before calling the original function. See the `HasTrampoline` property. In both cases, calls to the original function will jump to the hook delegate when the hook is installed. The delegate can be either an `[UnmanagedCallersOnly]` method or a managed delegate with the same signature as the exported function.

In the sample, all calls to `ReadFile` within notepad.exe's process will call `ReadFile_hook`. `ReadFile_hook` peeks at the parameters, calls `Kernelbase.ReadFile`,  and then returns the file handle.

```C#
using BOOL = System.Int32;

static INativeHook? ReadFileHook;
static delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL> ReadFile_original;

public static int Bootstrap(IntPtr argument, int size)
{
    delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL> hook2 = &ReadFile_hook;
    ReadFileHook
        = currentProc
        .GetModulesByName("kernel32")
        .FirstOrDefault()
        ?.GetExportByName("ReadFile")
        ?.Hook(hook2);

    if (ReadFileHook is not null)
        ReadFile_original =
            (delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL>)
            ReadFileHook.OriginalFunction;
}
[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
static BOOL ReadFile_hook(IntPtr hFile, byte* lpBuffer, int nNumberOfBytesToWrite, int* lpNumberOfBytesWritten, IntPtr lpOverlapped)
{
	var result = ReadFile_original(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	return result;
}
```
## Hooking Arbitrary Addresses

You may install a hook at any address using `JumpHook.Create()`.

## Breakpoint Hooks

You may perform hooking using i386 hardware breakpoints. `BreakpointHook` is thread-specific because it relies on the CPU's debug registers being set in the thread's context. You're also limited to four breakpoints per thread. Additionally, you will almost certainly not be able to debug the hook function because the hardware breakpoint will notify the debugger of a stop and it will deadlock.

```C#
static INativeHook? CreateFileWHook;
static delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr> CreateFileW_original;

public static int Bootstrap(IntPtr argument, int size)
{
    var firstThread = currentProc.Threads.Cast<ProcessThread>().MinBy(t => t.StartTime);

    delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr> hook3 = &CreateFileW_hook;
    CreateFileWHook
        = currentProc
        .GetModulesByName("kernel32")
        .FirstOrDefault()
        ?.GetExportByName("CreateFileW")
        ?.Hook(hook3, firstThread, installAfterCreate: false);

    if (CreateFileWHook?.OriginalFunction is not null or 0)
    {
        CreateFileW_original =
            (delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr>)
            CreateFileWHook.OriginalFunction;

        CreateFileWHook.InstallHook();
    }
}

[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
static IntPtr CreateFileW_hook(
    IntPtr lpFileName, uint dwDesiredAccess, uint dwShareMode,
    IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile)
{
	var result
	= CreateFileW_original(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);

	return result;
}
```

## See the samples for useage.
There are two sample projects:
- **SampleInjected** - A .NET 6.0 dll to be injected into a native process and uses `InjectDotnet.NativeHelper` to hook native functions.
- **SampleInjector** - The program that uses `InjectDotnet` to inject `SampleInjected` into Windows notepad.exe and pass it two strings and a png image as arguments. Executes `SampleInjected.Program.Bootstrap` after injection. 

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

