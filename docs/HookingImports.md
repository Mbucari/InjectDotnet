# Hooking Imported Functions
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
