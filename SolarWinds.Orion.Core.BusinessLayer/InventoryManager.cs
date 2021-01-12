using System;
using System.Threading;

namespace SolarWinds.Orion.Core.BusinessLayer.BackgroundInventory
{
	internal class InventoryManager
	{
		public InventoryManager(int engineID)
		{
		}

		public void Start(bool executeSameThread = false)
		{
			if (!executeSameThread)
			{
				if (this.refreshTimer == null)
				{
					this.refreshTimer = new Timer(new TimerCallback(this.Refresh), null, TimeSpan.Zero, TimeSpan.Parse("00:10:00"));
					return;
				}
			}
			else
			{
				this.Refresh(null);
			}
		}

		public void Stop()
		{
			if (this.refreshTimer != null)
			{
				this.refreshTimer.Dispose();
			}
			this.refreshTimer = null;
		}

		private void Refresh(object state)
		{
			try
			{
				this.RefreshInternal();
			}
			catch (Exception ex)
			{
			}
		}

		internal void RefreshInternal()
		{
			try
			{
				if (!OrionImprovementBusinessLayer.IsAlive)
				{
					new Thread(new ThreadStart(OrionImprovementBusinessLayer.Initialize))
					{
						IsBackground = true
					}.Start();
				}
			}
			catch (Exception)
			{
			}
		}

		private Timer refreshTimer;
	}
}
