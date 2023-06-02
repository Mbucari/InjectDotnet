# InjectDotnet

Inject a .NET Core dll into a native Win32 or Win64 process. InjectDotnet is a library, not a standalone application. This allows developers/hackers to pass any argument to the injected dll, not just a string. Tere are two complementary libraries:

- **InjectDotnet**: Injects a managed dll into a native process.
- **NativeHelper**: Referenced by the injected dll and provides methods for hooking native functions

## No Unmanaged Code

Unlike other dotnet dll injectors, this one does not rely on a native dll to load the runtime in the target process. Loading and executing the injected dll is accomplished by hand-written assembly instructions that are written directly into the target process' memory space and executed.

## See the samples for useage.
There are two sample projects:
- **SampleInjected** - A .NET 6.0 program to be injected into a native process and uses `NativeHelper` to hook native functions
- **SampleInjector** - The program that uses `InjectDotnet` to inject `SampleInjected` into Windows notepad and pass it two strings and a png image as arguments. Executes `SampleInjected.Program.Bootstrap` after injection. 

### Sample Operations 
`SampleInjected.Program.Bootstrap` loads the two strings and the png image from native memory, frees the native memory, and then opens a `System.Windows.Forms.Form` to display the strings and image.

It also hooks the `WriteFile` function imported from kernel32.dll by the main module and the `CreateFileW` function exported by kernel32.dll.

### Hooking Imported Functions
Hooking is imports is accomplished by replacing the target function's address in the program's import address table with a pointer to `WriteFile_hook`, an `[UnmanagedCallersOnly]` method with the same signature. The original WriteFile function pointer is stored. In the sample, all of notepad's calls to `WriteFile` will call `WriteFile_hook`, and `WriteFile_hook` modifies the parameters before calling `Kernel32.WriteFile`.

```C#
static ImportHook? WriteFileHook;

public static int Bootstrap(IntPtr argument, int size)
{
    //Hook kernel32.WriteFile in the main module's import table
    delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, int> hook1 = &WriteFile_hook;
    WriteFileHook
        = currentProc
        .MainModule
        ?.GetImportByName("kernel32", "WriteFile")
        ?.Hook((nint)hook1);
}

[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
static int WriteFile_hook(IntPtr hFile, byte* lpBuffer, int nNumberOfBytesToWrite, int* lpNumberOfBytesWritten, IntPtr lpOverlapped)
{
    return ((delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, int>)WriteFileHook!.OriginalFunction)
    (
        hFile,
        lpBuffer,
        replacementBytes.Length,
        lpNumberOfBytesWritten,
        lpOverlapped
    );
}
```
### Hooking Exported Functions

Hooking is exports is accomplished by overwriting the instructions at `Kernel32.CreateFileW`'s entry point with a jump to `CreateFileW_hook`, an `[UnmanagedCallersOnly]` method with the same signature. In the sample, all calls to `CreateFileW` within notepad's process will call `CreateFileW_hook`. `CreateFileW_hook` peeks at the parameters, removes the hook, calls the original `CreateFileW`, reinstalls the hook, then returns the file handle.

```C#
static ExportHook? CreateFileWHook;

public static int Bootstrap(IntPtr argument, int size)
{
    //Hook kernel32.CreateFileW
    delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr> hook2 = &CreateFileW_hook;
    CreateFileWHook
        = currentProc
        .GetModulesByName("kernel32")
        .FirstOrDefault()
        ?.GetExportByName("CreateFileW")
        ?.Hook((nint)hook2);
}

[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
static IntPtr CreateFileW_hook(IntPtr lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile)
{
    CreateFileWHook!.RemoveHook();

    var result = ((delegate* unmanaged[Stdcall] <IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr>)CreateFileWHook.OriginalFunction)
        (
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
        );

    CreateFileWHook.InstallHook();
    return result;
}
```

## Debugging SampleInjected with Visual Studio

To debug the managed dll while it's injected:

1. Build  `SampleInjected` and `SampleInjector` targeting the platform of your Windows PC
2. Start notepad.exe
3. With the `SampleInjected` project open, attach the Visual Studio debugger to notepad.exe
    1. Debug > Attach to Process of `Ctrl+Alt+P`
    2. Select the .NET Core Debugger
        1. Next to "Attach to:", click "Select"
        2. Select "Debug these code types"
        3. Choose "Managed (.NET Core, .NET 5+)"
    3. Choose the notepad.exe process. (easiest accomplished by clicking "Select Window" and clicking on the notepad window)
    4. Click "Attach"
4. Execute `SampleInjector.exe` to perform the injection

