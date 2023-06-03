# InjectDotnet

Inject a .NET Core dll into a native Win32 or Win64 process. InjectDotnet is a library, not a standalone application. This allows developers/hackers to pass any argument to the injected dll, not just a string. There are two complementary libraries:

- **InjectDotnet**: Injects a managed dll into a native process.
- **InjectDotnet.NativeHelper**: Referenced by the injected dll and provides methods for hooking native functions

## No Unmanaged Libraries

Unlike other dotnet dll injectors, this one does not rely on a native dll to load the runtime in the target process. Loading and executing the injected dll is accomplished by hand-written assembly instructions that are written directly into the target process' memory space and executed.

## Hooking Imported Functions
Hooking imports is accomplished by replacing the target function's address in a module's import address table with a pointer to the hook delegate. The hook delegate can be either an `[UnmanagedCallersOnly]` method or a managed delegate with the same signature as the imported function. The original function pointer is stored in `ImportHook.OriginalFunction` and can be called by creating a delegate for it.

In the sample, all of notepad.exe's calls to `WriteFile` will call `WriteFile_hook`, and `WriteFile_hook` modifies the parameters before calling `Kernel32.WriteFile`.

```C#
static ImportHook? WriteFileHook;
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

Hooking exports is accomplished by overwriting the original function's entry point instructions with a jump to the hook delegate. The delegate can be either an `[UnmanagedCallersOnly]` method or a managed delegate with the same signature as the exported function. This is a destructive act and, unlike hooked imports, the original function cannot be called without first removing the hook via `ExportHook.RemoveHook()`. If the export points to an entry in a jump table, however, you may work around this limitation by creating a delegate for the original function at the target of that jump. Many Winapi functions exported by kernel32, for instance, are jumps to identically named functions in kernelbase.

In the sample, all calls to `CreateFileW` within notepad.exe's process will call `CreateFileW_hook`. `CreateFileW_hook` peeks at the parameters, calls `Kernelbase.CreateFileW`,  and then returns the file handle.

```C#
static ExportHook? CreateFileWHook;
static delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr> CreateFileW_original;

public static int Bootstrap(IntPtr argument, int size)
{
    //Hook kernel32.CreateFileW
    delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr> hook2 = &CreateFileW_hook;
    CreateFileWHook
        = Process
        .GetCurrentProcess()
        .GetModulesByName("kernel32")
        .FirstOrDefault()
        ?.GetExportByName("CreateFileW")
        ?.Hook(hook2);

    //kernel32.CreateFileW forwards to kernelbase.CreateFileW;
    CreateFileW_original =
        (delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr>)
        NativeLibrary.GetExport(NativeLibrary.Load("kernelbase"), "CreateFileW");
}

[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
static IntPtr CreateFileW_hook(
    IntPtr lpFileName,
    uint dwDesiredAccess,
    uint dwShareMode,
    IntPtr lpSecurityAttributes,
    uint dwCreationDisposition,
    uint dwFlagsAndAttributes,
    IntPtr hTemplateFile)
{
    var result
        = CreateFileW_original is null ? IntPtr.Zero
        : CreateFileW_original(
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
- **SampleInjected** - A .NET 6.0 program to be injected into a native process and uses `InjectDotnet.NativeHelper` to hook native functions.
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

