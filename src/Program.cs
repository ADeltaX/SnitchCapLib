using System;
using System.Collections.Generic;

namespace SnitchCap
{
    class Program
    {
        static void Main(string[] args)
        {
            Snitch("microphone");
            Snitch("webcam");
            Snitch("location");

            Console.WriteLine(" - Snitcher started - ");

            Console.Read();
        }

        private static void Snitch(string capNameToSnitch)
        {
            CapUsageSnitcher snitcher = new CapUsageSnitcher(capNameToSnitch);
            PrintChanges(snitcher.SnitchPackages(), true);

            snitcher.CapUsageChanged += Snitcher_CapChanged;
            snitcher.StartSnitching();
        }

        private static void PrintChanges(List<CapSnitchApp> capSnitchApps, bool ignoreNonInUse)
        {
            capSnitchApps.ForEach(pkg =>
            {
                if (pkg.IsInUse)
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}][SNITCH] {pkg.AppName} is accessing {pkg.CapabilityName}!");
                else if (!ignoreNonInUse)
                    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}][SNITCH] {pkg.AppName} stopped accessing {pkg.CapabilityName}!");
            });
        }

        private static void Snitcher_CapChanged(object sender, CapUsageChangedEventArgs e)
        {
            PrintChanges(e.CapUsageChanged, false);
        }
    }
}
