# Hooking Exported Functions (Jump Hooks)

Hooking exports is accomplished by overwriting the original function's entry point instructions with a jump to a block of memory allocated nearby. NativeHelper will attempt to create a trampoline (using a C# port of [minhook](https://github.com/TsudaKageyu/minhook)). If successdul, the original function may be called without removing the hook. If trampoline creation failed, the hook must be removed via `RemoveHook()` before calling the original function. See the `HasTrampoline` property. In both cases, calls to the original function will jump to the hook delegate when the hook is installed. The delegate can be either an `[UnmanagedCallersOnly]` method or a managed delegate with the same signature as the exported function.

In the sample, all calls to `ReadFile` within notepad.exe's process will call `ReadFile_hook`. `ReadFile_hook` peeks at the parameters, calls `Kernelbase.ReadFile`,  and then returns the file handle.

You may create a jump hook for an arbitrary instruction using `JumpHook.Create()`.

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
