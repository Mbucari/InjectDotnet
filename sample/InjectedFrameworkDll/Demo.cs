using System;
using System.Windows.Forms;
using System.Linq;

namespace InjectedFrameworkDll
{
    public class Demo
    {
		public static int Bootstrap(string arg)
		{
			MessageBox.Show(string.Join("\r\n", AppDomain.CurrentDomain.GetAssemblies().Select(x => x.FullName)));
			return 0x1337;
		}
	}
}
