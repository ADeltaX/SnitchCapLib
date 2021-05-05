using SnitchCapLib;
using System;
using System.Collections.Generic;

namespace SnitchCap
{
    class Program
    {
        static void Main(string[] args)
        {
            var snitchMicrophone = Snitch("microphone");
            var snitchWebcam = Snitch("webcam");
            var snitchLocation = Snitch("location");

            Console.WriteLine(" - Snitcher started - ");

            PrintChanges(snitchMicrophone.SnitchPackages(), true);
            PrintChanges(snitchWebcam.SnitchPackages(), true);
            PrintChanges(snitchLocation.SnitchPackages(), true);

            Console.Read();

            snitchMicrophone.Dispose();
            snitchWebcam.Dispose();
            snitchLocation.Dispose();
        }

        private static CapUsageSnitcher Snitch(string capNameToSnitch)
        {
            CapUsageSnitcher snitcher = new CapUsageSnitcher(capNameToSnitch);

            snitcher.CapUsageChanged += Snitcher_CapChanged;
            snitcher.StartSnitching();

            return snitcher;
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
