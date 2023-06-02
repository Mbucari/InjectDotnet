namespace InjectDotnet.NativeHelper;

/// <summary>And instance of a hooked native function</summary>
public interface INativeHook
{
	/// <summary>Entry point of the function being hooked</summary>
	nint OriginalFunction { get; }
	/// <summary>Whether <see cref="OriginalFunction"/> is currently hooked</summary>
	bool IsHooked { get; }

	/// <summary>Hook the <see cref="OriginalFunction"/></summary>
	/// <returns>Success</returns>
	bool InstallHook();

	/// <summary>Remove the <see cref="OriginalFunction"/> hook</summary>
	/// <returns>Success</returns>
	bool RemoveHook();
}
