using InjectDotnet.NativeHelper.Native;
using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper;

public static class Permission
{
	/// <summary>
	/// Adjust this process's access tokens to grant it SE_PRIVILEGE_ENABLED
	/// </summary>
	/// <returns>Success</returns>
	public static bool GetDebugPrivileges()
	{
		SafeAccessTokenHandle currentToken;
		if (NativeMethods.OpenProcessToken(Process.GetCurrentProcess().SafeHandle, TokenAccessRights.TOKEN_ADJUST_PRIVILEGES | TokenAccessRights.TOKEN_READ | TokenAccessRights.TOKEN_QUERY | TokenAccessRights.TOKEN_QUERY_SOURCE, out currentToken))
		{
			var newPrivs = new LUID_AND_ATTRIBUTES[3];
			NativeMethods.LookupPrivilegeValue(null, PrivelageNames.SE_DEBUG_NAME, out newPrivs[2].Luid);
			NativeMethods.LookupPrivilegeValue(null, PrivelageNames.SE_CREATE_PAGEFILE_NAME, out newPrivs[1].Luid);

			if (NativeMethods.LookupPrivilegeValue(null, PrivelageNames.SE_AUDIT_NAME, out newPrivs[0].Luid))
			{
				newPrivs[0].Attributes = LUIDPrivileges.SE_PRIVILEGE_ENABLED;
				newPrivs[1].Attributes = LUIDPrivileges.SE_PRIVILEGE_ENABLED;
				newPrivs[2].Attributes = LUIDPrivileges.SE_PRIVILEGE_ENABLED;

				if (NativeMethods.AdjustTokenPrivileges(currentToken, false, newPrivs, out var previous))
				{
					var sss = NativeMethods.PrivilegeCheck(currentToken, newPrivs);
					NativeMethods.AdjustTokenPrivileges(currentToken, false, newPrivs, out previous);
					currentToken.Close();
					return true;
				}
			}
			return false;
		}
		return false;
	}
}
class PrivelageNames
{
	public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
	public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
	public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
	public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
	public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";
	public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
	public const string SE_TCB_NAME = "SeTcbPrivilege";
	public const string SE_SECURITY_NAME = "SeSecurityPrivilege";
	public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
	public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
	public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
	public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
	public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
	public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
	public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
	public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
	public const string SE_BACKUP_NAME = "SeBackupPrivilege";
	public const string SE_RESTORE_NAME = "SeRestorePrivilege";
	public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
	public const string SE_DEBUG_NAME = "SeDebugPrivilege";
	public const string SE_AUDIT_NAME = "SeAuditPrivilege";
	public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
	public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
	public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
	public const string SE_UNDOCK_NAME = "SeUndockPrivilege";
	public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
	public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
	public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
	public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
}

[Flags]
public enum ThreadRights : uint
{
	READ_CONTROL = StandardAccessRights.READ_CONTROL,
	SYNCHRONIZE = StandardAccessRights.SYNCHRONIZE,
	WRITE_DAC = StandardAccessRights.WRITE_DAC,
	WRITE_OWNER = StandardAccessRights.WRITE_OWNER,

	THREAD_TERMINATE = 0x0001,
	THREAD_SUSPEND_RESUME = 0x0002,
	THREAD_GET_CONTEXT = 0x0008,
	THREAD_SET_CONTEXT = 0x0010,
	THREAD_SET_INFORMATION = 0x0020,
	THREAD_QUERY_INFORMATION = 0x0040,
	THREAD_SET_THREAD_TOKEN = 0x0080,
	THREAD_IMPERSONATE = 0x0100,
	THREAD_DIRECT_IMPERSONATION = 0x0200,
	THREAD_SET_LIMITED_INFORMATION = 0x0400,
	THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
	THREAD_RESUME = 0x1000,
	THREAD_ALL_ACCESS = (StandardAccessRights.STANDARD_RIGHTS_REQUIRED | StandardAccessRights.SYNCHRONIZE | 0xffff)
}

[Flags]
public enum TokenAccessRights : uint
{
	TOKEN_ADJUST_GROUPS = 0x0040,
	TOKEN_ADJUST_PRIVILEGES = 0x0020,
	TOKEN_ADJUST_SESSIONID = 0x0100,
	TOKEN_ASSIGN_PRIMARY = 0x0001,
	TOKEN_DUPLICATE = 0x0002,
	TOKEN_EXECUTE = StandardAccessRights.STANDARD_RIGHTS_EXECUTE,
	TOKEN_IMPERSONATE = 0x0004,
	TOKEN_QUERY = 0x0008,
	TOKEN_QUERY_SOURCE = 0x0010,
	TOKEN_ADJUST_DEFAULT = 0x0080,
	TOKEN_READ = (StandardAccessRights.STANDARD_RIGHTS_READ | TOKEN_QUERY),
	TOKEN_WRITE = (StandardAccessRights.STANDARD_RIGHTS_WRITE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT),
	TOKEN_ALL_ACCESS = (StandardAccessRights.STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT)
}

[Flags]
public enum StandardAccessRights : uint
{
	DELETE = 0x00010000,
	READ_CONTROL = 0x00020000,
	WRITE_DAC = 0x00040000,
	WRITE_OWNER = 0x00080000,
	SYNCHRONIZE = 0x00100000,

	STANDARD_RIGHTS_REQUIRED = 0x000f0000,
	STANDARD_RIGHTS_READ = READ_CONTROL,
	STANDARD_RIGHTS_WRITE = READ_CONTROL,
	STANDARD_RIGHTS_EXECUTE = READ_CONTROL,
	STANDARD_RIGHTS_ALL = 0x001f0000,
}


[StructLayout(LayoutKind.Sequential)]
public class TOKEN_PRIVILEGES : ICloneable
{
	private static int initialSize = sizeof(int) + Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
	public int PrivilegeCount { get; internal set; }
	public LUID_AND_ATTRIBUTES[] LuidAndAttribs { get; internal set; }

	public TOKEN_PRIVILEGES() : this(initialSize)
	{

	}
	public TOKEN_PRIVILEGES(int requiredSize)
	{
		int arraySize = requiredSize - sizeof(int);

		PrivilegeCount = arraySize / Marshal.SizeOf<LUID_AND_ATTRIBUTES>();

		LuidAndAttribs = new LUID_AND_ATTRIBUTES[PrivilegeCount];
	}
	public int Size => sizeof(int) + Marshal.SizeOf<LUID_AND_ATTRIBUTES>() * LuidAndAttribs.Length;

	public string PrivilegeName(LUID luid)
	{
		System.Text.StringBuilder strBuffer = new System.Text.StringBuilder(80);
		int sbSize = strBuffer.Capacity;
		NativeMethods.LookupPrivilegeName(null, ref luid, strBuffer, ref sbSize);
		return strBuffer.ToString();
	}
	public object Clone()
	{
		TOKEN_PRIVILEGES clone = new TOKEN_PRIVILEGES();

		clone.PrivilegeCount = PrivilegeCount;
		clone.LuidAndAttribs = new LUID_AND_ATTRIBUTES[LuidAndAttribs.Length];
		Array.Copy(LuidAndAttribs, clone.LuidAndAttribs, LuidAndAttribs.Length);

		return clone;
	}
}
[StructLayout(LayoutKind.Sequential)]
public struct LUID_AND_ATTRIBUTES
{
	public LUID Luid;
	public LUIDPrivileges Attributes;

}

[StructLayout(LayoutKind.Sequential, Size = 8)]
public struct LUID
{
	public uint LowPart;
	public int HighPart;
}

[Flags]
public enum LUIDPrivileges : uint
{
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
	SE_PRIVILEGE_ENABLED = 0x00000002,
	SE_PRIVILEGE_REMOVED = 0x00000004,
	SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
}

public class TokenPrivilegesCustomMarshaler : ICustomMarshaler
{
	[ThreadStatic]
	TOKEN_PRIVILEGES marshaledObject;

	static TokenPrivilegesCustomMarshaler static_instance;
	public static ICustomMarshaler GetInstance(string cookie)
	{
		if (static_instance == null)
		{
			return static_instance = new TokenPrivilegesCustomMarshaler();
		}
		return static_instance;
	}
	public void CleanUpManagedData(object ManagedObj)
	{

	}
	public void CleanUpNativeData(IntPtr pNativeData)
	{
		Marshal.FreeHGlobal(pNativeData);
	}

	public int GetNativeDataSize()
	{
		return -1;
	}
	public IntPtr MarshalManagedToNative(object managedObj)
	{
		if (managedObj == null)
			return IntPtr.Zero;
		if (managedObj is not TOKEN_PRIVILEGES marshaledObject)
			throw new MarshalDirectiveException($"{this.GetType().Name} must be used on {typeof(TOKEN_PRIVILEGES).Name}.");

		IntPtr structHandle = Marshal.AllocHGlobal(marshaledObject.Size);
		Marshal.WriteInt32(structHandle, marshaledObject.PrivilegeCount);

		for (int i = 0; i < marshaledObject.PrivilegeCount; i++)
		{
			Marshal.WriteInt32(structHandle, i * Marshal.SizeOf<LUID_AND_ATTRIBUTES>() + 4, (int)marshaledObject.LuidAndAttribs[i].Luid.LowPart);
			Marshal.WriteInt32(structHandle, i * Marshal.SizeOf<LUID_AND_ATTRIBUTES>() + 8, marshaledObject.LuidAndAttribs[i].Luid.HighPart);
			Marshal.WriteInt32(structHandle, i * Marshal.SizeOf<LUID_AND_ATTRIBUTES>() + 12, (int)marshaledObject.LuidAndAttribs[i].Attributes);
		}
		return structHandle;
	}
	public object MarshalNativeToManaged(IntPtr pNativeData)
	{
		if (marshaledObject == null)
			throw new MarshalDirectiveException("This marshaler can only be used for in-place ([In. Out]) marshaling.");

		marshaledObject.PrivilegeCount = Marshal.ReadInt32(pNativeData);

		for (int i = 0; i < marshaledObject.PrivilegeCount; i++)
		{
			marshaledObject.LuidAndAttribs[i].Luid.LowPart = (uint)Marshal.ReadInt32(pNativeData, i * Marshal.SizeOf<LUID_AND_ATTRIBUTES>() + 4);
			marshaledObject.LuidAndAttribs[i].Luid.HighPart = Marshal.ReadInt32(pNativeData, i * Marshal.SizeOf<LUID_AND_ATTRIBUTES>() + 8);
			marshaledObject.LuidAndAttribs[i].Attributes = (LUIDPrivileges)Marshal.ReadInt32(pNativeData, i * Marshal.SizeOf<LUID_AND_ATTRIBUTES>() + 12);
		}
		return marshaledObject;
	}
}
