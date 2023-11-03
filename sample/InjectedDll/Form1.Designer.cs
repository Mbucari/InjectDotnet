namespace InjectedDll
{
	partial class Form1
	{
		/// <summary>
		///  Required designer variable.
		/// </summary>
		private System.ComponentModel.IContainer components = null;

		/// <summary>
		///  Clean up any resources being used.
		/// </summary>
		/// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing && (components != null))
			{
				components.Dispose();
			}
			base.Dispose(disposing);
		}

		#region Windows Form Designer generated code

		/// <summary>
		///  Required method for Designer support - do not modify
		///  the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
			pictureBox1 = new PictureBox();
			label1 = new Label();
			listView1 = new ListView();
			lvcFunction = new ColumnHeader();
			lvcLog = new ColumnHeader();
			lvcTimestamp = new ColumnHeader();
			((System.ComponentModel.ISupportInitialize)pictureBox1).BeginInit();
			SuspendLayout();
			// 
			// pictureBox1
			// 
			pictureBox1.Anchor = AnchorStyles.Top | AnchorStyles.Right;
			pictureBox1.BackgroundImageLayout = ImageLayout.None;
			pictureBox1.Location = new Point(370, 4);
			pictureBox1.Margin = new Padding(2, 0, 2, 0);
			pictureBox1.Name = "pictureBox1";
			pictureBox1.Size = new Size(108, 110);
			pictureBox1.SizeMode = PictureBoxSizeMode.Zoom;
			pictureBox1.TabIndex = 0;
			pictureBox1.TabStop = false;
			// 
			// label1
			// 
			label1.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
			label1.Location = new Point(6, 4);
			label1.Margin = new Padding(2, 0, 2, 0);
			label1.Name = "label1";
			label1.Size = new Size(358, 110);
			label1.TabIndex = 1;
			label1.Text = "label1";
			// 
			// listView1
			// 
			listView1.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
			listView1.Columns.AddRange(new ColumnHeader[] { lvcTimestamp, lvcFunction, lvcLog });
			listView1.Location = new Point(6, 117);
			listView1.Name = "listView1";
			listView1.Size = new Size(472, 279);
			listView1.TabIndex = 2;
			listView1.UseCompatibleStateImageBehavior = false;
			listView1.View = View.Details;
			// 
			// lvcFunction
			// 
			lvcFunction.Text = "Function";
			// 
			// lvcLog
			// 
			lvcLog.Text = "Log";
			lvcLog.Width = 200;
			// 
			// lvcTimestamp
			// 
			lvcTimestamp.Text = "Timestamp";
			// 
			// Form1
			// 
			AutoScaleDimensions = new SizeF(7F, 15F);
			AutoScaleMode = AutoScaleMode.Font;
			ClientSize = new Size(487, 400);
			Controls.Add(listView1);
			Controls.Add(label1);
			Controls.Add(pictureBox1);
			Margin = new Padding(2, 1, 2, 1);
			Name = "Form1";
			Text = "Hook Viewer";
			((System.ComponentModel.ISupportInitialize)pictureBox1).EndInit();
			ResumeLayout(false);
		}

		#endregion

		public Label label1;
		public PictureBox pictureBox1;
		private ListView listView1;
		private ColumnHeader lvcFunction;
		private ColumnHeader lvcLog;
		private ColumnHeader lvcTimestamp;
	}
}