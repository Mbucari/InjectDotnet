namespace InjectDotnet.NativeHelper;

/// <summary>An instance of a hooked native function</summary>
public interface INativeHook
{
	/// <summary>Entry point of the function being hooked</summary>
	nint OriginalFunction { get; }
	/// <summary>Get or set the hook status of <see cref="OriginalFunction"/></summary>
	bool IsHooked { get; set; }

	/// <summary>Address of the delegate that is hooking <see cref="OriginalFunction"/></summary>
	nint HookFunction { get; }

	/// <summary>Hook the <see cref="OriginalFunction"/></summary>
	/// <returns>Success</returns>
	bool InstallHook();

	/// <summary>Remove the <see cref="OriginalFunction"/> hook</summary>
	/// <returns>Success</returns>
	bool RemoveHook();
}
