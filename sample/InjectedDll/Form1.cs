namespace InjectedDll;

public partial class Form1 : Form
{
	public Form1()
	{
		InitializeComponent();
	}

	public async void LogFunction(string timeStamp, string functionName, string logMessage)
	{
		var result = BeginInvoke(() =>
		{
			var newItem = listView1.Items.Add(new ListViewItem(new string[] { timeStamp, functionName, logMessage }));
			listView1.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
			newItem.EnsureVisible();
		});

		await Task.Factory.FromAsync(result, EndInvoke);
	}
}