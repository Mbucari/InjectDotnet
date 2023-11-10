# Breakpoint Hooks

You may perform hooking using i386 hardware breakpoints. `BreakpointHook` is thread-specific because it relies on the CPU's debug registers being set in the thread's context. You're also limited to four breakpoints per thread. 

Additionally, you will not be able to debug the hooking function. The attached debugger will see the hardware breakpoint as a Single Step debug event and will either handle it (so `BreakpointHook` cannot handle it), or it will wait indefinitely for user input before continuing (resulting in deadlock). For this reason, `BreakpointHook` will throw an exception if the process is being debugged.

```C#
static INativeHook? CreateFileWHook;
static delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr> CreateFileW_original;

public static int Bootstrap(IntPtr argument, int size)
{
    using var currentProc = Process.GetCurrentProcess();
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
