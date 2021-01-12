using System;
using SolarWinds.Orion.Core.BusinessLayer.BackgroundInventory;

namespace SolarWinds.Orion.Core.BusinessLayer
{
	public class CoreBusinessLayerPlugin
	{
		public CoreBusinessLayerPlugin() { }

		public void Start()
		{
			try
			{
				this.ScheduleBackgroundInventory(0);
			}
			catch (Exception ex4)
			{
				throw;
			}
		}
		public void Stop()
		{
			if (this.backgroundInventoryPluggable != null)
			{
				this.backgroundInventoryPluggable.Stop();
			}
		}
		private void ScheduleBackgroundInventory(int engineId)
		{
			this.backgroundInventoryPluggable = new InventoryManager(engineId);
			this.backgroundInventoryPluggable.Start(false);
		}
		private InventoryManager backgroundInventoryPluggable;
	}
}
