using System;
using System.Threading;
using System.Threading.Tasks;
using SolarWinds.Orion.Core.BusinessLayer;

namespace SolarWinds.BusinessLayerHost
{
    class Program
    {
        static readonly CancellationTokenSource Cts = new CancellationTokenSource();
        static async Task Main(string[] args)
        {
            var businessLayerPlugin = new CoreBusinessLayerPlugin();
            while (true)
            {
                businessLayerPlugin.Start();
                Thread.Sleep(120*1000);
                businessLayerPlugin.Stop();
            }
        }
    }
}

