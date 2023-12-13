namespace InjectDotnet;

internal interface IManagedLoader
{
	/// <summary>
	/// Pointer to the machine code stub in the target process which loads the runtime and executes the injected entry point.
	/// </summary>
	nint Loader { get; }
	/// <summary>
	/// Pointer to a structure in the target process which is passed to <see cref="Loader"/> as the first argument.
	/// </summary>
	nint Parameter { get; }
}
