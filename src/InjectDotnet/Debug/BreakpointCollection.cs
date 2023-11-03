using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;

namespace InjectDotnet.Debug;

/// <summary>
/// A collection of user-defined <see cref="Debugger"/> breakpoints.
/// </summary>
public class BreakpointCollection : ObservableCollection<UserBreakpoint>
{
	public BreakpointCollection() : base(new List<UserBreakpoint>()) { }

	protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
	{
		base.OnCollectionChanged(e);

		if (e.Action is NotifyCollectionChangedAction.Remove or NotifyCollectionChangedAction.Replace
			&& e.OldItems?.OfType<UserBreakpoint>() is IEnumerable<UserBreakpoint> bps)
		{
			foreach (var bp in bps)
			{
				bp.TryDisable();
			}
		}
	}

	/// <summary>
	/// Gets a <see cref="UserBreakpoint"/> set at a specified address.
	/// </summary>
	/// <param name="address">address at when the breakpoint is set</param>
	/// <returns>The <see cref="UserBreakpoint"/> at the address is one exists in the collection, otherwise null</returns>
	public UserBreakpoint? GetByAddress(nint address)
		=> this.SingleOrDefault(bp => bp.Address == address);

	protected override void ClearItems()
	{
		foreach (var bp in this)
			bp.TryDisable();
		base.ClearItems();
	}

	protected override void RemoveItem(int index)
	{
		this[index].TryDisable();
		base.RemoveItem(index);
	}

	protected override void InsertItem(int index, UserBreakpoint item)
	{
		if (this.Any(bp => bp.Address == item.Address))
			return;

		base.InsertItem(index, item);
	}
}
