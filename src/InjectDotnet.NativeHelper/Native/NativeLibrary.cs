using System;

namespace InjectDotnet.NativeHelper.Native
{
    internal class NativeLibrary
    {
        public static bool TryLoad(string libraryPath, out IntPtr handle)
        {
            handle = NativeMethods.LoadLibrary(libraryPath);
            return handle != IntPtr.Zero;
        }
        public static bool TryGetExport(IntPtr handle, string name, out IntPtr address)
        {
			address = NativeMethods.GetProcAddress(handle, name);
            return address != IntPtr.Zero;
        }
    }
}
