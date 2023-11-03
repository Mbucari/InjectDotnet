using System;
using System.Runtime.InteropServices;
using System.Text;

namespace InjectDotnet.Native;

public static class NativeExtensions
{
	public static unsafe T ReadStruct<T>(this IMemoryReader memoryReader, nint address)
		where T : unmanaged
	{
		T val = default;
		var upBytes = new Span<byte>(&val, sizeof(T));
		memoryReader.ReadMemory(address, upBytes);
		return val;
	}

	public static nint ReadPtr(this IMemoryReader memoryReader, nint address)
	{
		Span<nint> buff = stackalloc nint[1];
		memoryReader.ReadMemory(address, MemoryMarshal.AsBytes(buff));
		return buff[0];
	}

	/// <summary>
	/// Read the image name from the target.
	/// </summary>
	/// <param name="reader">access to target's memory</param>
	/// <returns>String for full path to image. Null if name not available</returns>
	/// <remarks>MSDN says this will never be provided for during Attach scenarios; nor for the first 1 or 2 dlls.</remarks>
	public static string? ReadImageNameFromTarget(this IImageName target, IMemoryReader reader)
	{
		if (target.ImageName is 0 or -1) return null;
		try
		{
			nint address = reader.ReadPtr(target.ImageName);
			if (address is 0 or -1) return null;

			var encoding = target.Unicode ? Encoding.Unicode : Encoding.ASCII;
			return reader.ReadNullTerminatedString(address, encoding);
		}
		catch (DataMisalignedException)
		{
			return null;
		}
		catch (InvalidOperationException)
		{
			return null;
		}
	}

	/// <summary>
	/// Read the log message from the target. 
	/// </summary>
	/// <param name="reader">interface to access debugee memory</param>
	/// <returns>string containing message or null if not available</returns>
	public static string? ReadMessageFromTarget(this OUTPUT_DEBUG_STRING_INFO debugInfo, IMemoryAccess reader)
	{
		//We can't rely on nDebugStringLength for long strings, so read null-terminated instead.
		var address = debugInfo.lpDebugStringData;
		var encoding = debugInfo.fUnicode == 0 ? Encoding.ASCII : Encoding.Unicode;
		return reader.ReadNullTerminatedString(address, encoding);
	}

	public static string? ReadNullTerminatedString(this IMemoryReader reader, nint address, Encoding encoding)
	{
		if (address is 0 or -1) return null;
		NativeMethods.GetSystemInfo(out var sysInfo);

		Span<byte> pageBuff = new byte[sysInfo.dwPageSize];
		var sb = new StringBuilder();

		ReadOnlySpan<byte> nullTerminator = encoding.GetBytes(new char[1]);

		try
		{
			while (true)
			{
				var readBuff = pageBuff.Slice((int)(address % sysInfo.dwPageSize));
				reader.ReadMemory(address, readBuff);

				var nullIndex = AlignedIndexOf(readBuff, nullTerminator);
				if (nullIndex == -1)
				{
					sb.Append(encoding.GetString(readBuff));
					//Advance to start of next page
					address += readBuff.Length;
				}
				else
				{
					sb.Append(encoding.GetString(readBuff.Slice(0, nullIndex)));
					break;
				}
			}
		}
		catch (DataMisalignedException)
		{
			return null;
		}
		catch (InvalidOperationException)
		{
			return null;
		}

		return sb.ToString();

		static int AlignedIndexOf(ReadOnlySpan<byte> span, ReadOnlySpan<byte> value)
		{
			for (int i = 0; i < span.Length - value.Length; i += value.Length)
			{
				int matches = 0;
				for (; matches < value.Length; matches++)
					if (span[i + matches] != value[matches])
						break;

				if (matches == value.Length)
					return i;
			}
			return -1;
		}
	}
}
