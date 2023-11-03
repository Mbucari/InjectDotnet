using System.Collections.Concurrent;

namespace InjectedDll
{
	public partial class Form1 : Form
	{
		private bool shown;
		readonly Task queueTask;
		readonly BlockingCollection<string[]> Queue = new();

		public Form1()
		{
			InitializeComponent();
			Shown += (_, _) => shown = true;
			FormClosing += (_, _) => Queue.CompleteAdding();
			queueTask = Task.Run(QueueLogger);
		}

		private void QueueLogger()
		{
			while (Queue.TryTake(out var log, -1) && !listView1.IsDisposed)
			{
				listView1.Invoke(() =>
				{
					var newItem = listView1.Items.Add(new ListViewItem(log));
					listView1.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
					newItem.EnsureVisible();
				});
			}
		}

		public void LogFunction(string timeStamp, string functionName, string logMessage)
		{
			if (!shown) return;
			Queue.Add(new string[] { timeStamp, functionName, logMessage });
		}
	}
}