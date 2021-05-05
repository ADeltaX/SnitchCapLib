using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SnitchCapLib
{
    /// <summary>
    /// App capability details
    /// </summary>
    public class CapSnitchApp
    {
        /// <summary>
        /// Executable path or package name when packaged
        /// </summary>
        public string AppName { get; set; }

        /// <summary>
        /// The accessing capability name
        /// </summary>
        public string CapabilityName { get; set; }

        /// <summary>
        /// If the app is packaged. If it is <see cref="AppName"/> will contain AUMID instead of executable path.
        /// </summary>
        public bool IsPackaged { get; set; }

        /// <summary>
        /// Is the app accessing the capability or not.
        /// </summary>
        public bool IsInUse { get; set; }
    }

    /// <summary>
    /// Provides a way to get app capability usage.
    /// </summary>
    public class CapUsageSnitcher : IDisposable
    {
        [DllImport("combase.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int RoGetActivationFactory(
            [MarshalAs(UnmanagedType.HString)] string activatableClassId,
            [In] ref Guid iid,
            [Out, MarshalAs(UnmanagedType.IInspectable)] out object factory);

        [DllImport("wincorlib.dll", EntryPoint = "#129", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetActivationFactoryByPCWSTR([MarshalAs(UnmanagedType.LPWStr)] string typeName, Guid typeGuid, out IUnknown ppOut);

        [DllImport("api-ms-win-core-winrt-string-l1-1-0.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WindowsCreateStringReference([MarshalAs(UnmanagedType.LPWStr)] string sourceString, int length, out IntPtr header, out IntPtr hString);

        [DllImport("api-ms-win-core-winrt-string-l1-1-0.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WindowsDeleteString(IntPtr hString);

        [ComImport, Guid("42947746-4ea0-48c2-9274-062ed61f8daa"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface ICapabilityUsageStatics
        {
            // Note: Invoking methods on ComInterfaceType.InterfaceIsIInspectable interfaces
            // is no longer supported in the CLR (.NET 5.0+), but can be simulated with IUnknown.
            void GetIids(out int iidCount, out IntPtr iids);
            void GetRuntimeClassName(out IntPtr className);
            void GetTrustLevel(out int trustLevel);

            ICapabilityUsage Create(/*[MarshalAs(UnmanagedType.HString)] string*/ IntPtr capabilityName);
        }

        [ComImport, Guid("a19979e0-a2c3-4a21-8610-a6d893ba4f86"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface ICapabilityUsage
        {
            // Note: Invoking methods on ComInterfaceType.InterfaceIsIInspectable interfaces
            // is no longer supported in the CLR (.NET 5.0+), but can be simulated with IUnknown.
            void GetIids(out int iidCount, out IntPtr iids);
            void GetRuntimeClassName(out IntPtr className);
            void GetTrustLevel(out int trustLevel);

            //stub
            void CreateSession();
            void CreatePackagedSession();
            void GetUsage();
            void GetUsageForNonPackagedClient();
            object GetUsageForNonPackagedClients(/*[MarshalAs(UnmanagedType.HString)] string*/ IntPtr capabilityName);

            //valid
            ulong GetWNFStateNameForChanges();
        }

        [ComImport, Guid("00000000-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IUnknown
        {

        }

        private readonly ICapabilityUsageStatics statics;
        private readonly ICapabilityUsage usage;
        private readonly GCHandle handle;

        private IntPtr subscription;
        private ulong wnf;
        private string capToSnitch;
        private List<CapSnitchApp> backstore;

        /// <summary>
        /// Creates an instance of <see cref="CapUsageSnitcher"/>.
        /// </summary>
        /// <param name="capabilityName">A capability name. Currently supported: 'microphone', 'webcam', 'location'.</param>
        public CapUsageSnitcher(string capabilityName)
        {
            capToSnitch = capabilityName;

            // typeof(ICapabilityUsageStatics).GUID    for net standard 2.0+
            Guid guidCapUsageStatics = new Guid("42947746-4ea0-48c2-9274-062ed61f8daa");
            string WinRTClassId = "Windows.Internal.CapabilityAccess.Management.CapabilityUsage";

            // I'm using this variant because .NET 5.0 doesn't support hstring marshalling :)
            GetActivationFactoryByPCWSTR(WinRTClassId, guidCapUsageStatics, out var fact);
            statics = (ICapabilityUsageStatics)fact;

            // Quick workaround for .NET 5.0 not having hstring marshalling support
            // (I am not willing to include the entire Cs/WinRT library.)
            WindowsCreateStringReference(capToSnitch, capToSnitch.Length,
                out _, out var hstring_capToSnitch);
            try
            {
                usage = statics.Create(hstring_capToSnitch);
            }
            finally
            {
                WindowsDeleteString(hstring_capToSnitch);
            }

            wnf = usage.GetWNFStateNameForChanges();
            backstore = SnitchPackages();
            handle = GCHandle.Alloc(this);
        }

        /// <summary>
        /// Start listening to capability usage changes
        /// </summary>
        public void StartSnitching()
        {
            var wnfStateData = WnfInterop.QueryWnf(wnf);
            subscription = WnfInterop.SubscribeWnf(wnf, WnfSnitcher, GCHandle.ToIntPtr(handle), wnfStateData.Changestamp);
        }

        /// <summary>
        /// Stop listening to capability usage changes
        /// </summary>
        public void StopSnitching()
        {
            if (subscription != IntPtr.Zero)
                WnfInterop.UnsubscribeWnf(subscription);
        }

        /// <summary>
        /// Get a list of apps that are accessing or have accessed a capability.
        /// </summary>
        /// <returns>A list of apps</returns>
        public List<CapSnitchApp> SnitchPackages()
        {
            List<CapSnitchApp> packageIsAccessingCapRightNow = new List<CapSnitchApp>();
            try
            {
                var regKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\" + capToSnitch, false);

                var subkeyNames = regKey.GetSubKeyNames();
                for (int i = 0; i < subkeyNames.Length; i++)
                {
                    var subkey = regKey.OpenSubKey(subkeyNames[i], false);
                    if (subkey != null)
                    {
                        if (subkeyNames[i] != "NonPackaged")
                        {
                            long? lastUsedTimeStop = (long?)subkey.GetValue("LastUsedTimeStop");
                            if (lastUsedTimeStop.HasValue && lastUsedTimeStop.Value == 0)
                                packageIsAccessingCapRightNow.Add(new CapSnitchApp { AppName = subkeyNames[i], CapabilityName = capToSnitch, IsInUse = true, IsPackaged = true });
                            else
                                packageIsAccessingCapRightNow.Add(new CapSnitchApp { AppName = subkeyNames[i], CapabilityName = capToSnitch, IsInUse = false, IsPackaged = true });
                        }
                        else
                        {
                            var subkeyNonPackaged = regKey.OpenSubKey(subkeyNames[i], false);
                            if (subkeyNonPackaged != null)
                            {
                                var subkeyNamesNonPackaged = subkeyNonPackaged.GetSubKeyNames();
                                foreach (var nonPkg in subkeyNamesNonPackaged)
                                {
                                    var subkeyNP = subkeyNonPackaged.OpenSubKey(nonPkg, false);

                                    if (subkeyNP != null)
                                    {
                                        long? lastUsedTimeStop = (long?)subkeyNP.GetValue("LastUsedTimeStop");
                                        if (lastUsedTimeStop.HasValue && lastUsedTimeStop.Value == 0)
                                            packageIsAccessingCapRightNow.Add(new CapSnitchApp { AppName = nonPkg.Replace("#", "\\"), CapabilityName = capToSnitch, IsInUse = true, IsPackaged = false });
                                        else
                                            packageIsAccessingCapRightNow.Add(new CapSnitchApp { AppName = nonPkg.Replace("#", "\\"), CapabilityName = capToSnitch, IsInUse = false, IsPackaged = false });

                                        subkeyNP.Dispose();
                                    }
                                }
                                subkeyNonPackaged.Dispose();
                            }
                        }

                        subkey.Dispose();
                    }
                }

                regKey.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception in SnitchPackages() --> " + ex.Message);
            }

            return packageIsAccessingCapRightNow;
        }

        /// <summary>
        /// Delegate for <see cref="CapUsageChangedEventHandler"/>.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        public delegate void CapUsageChangedEventHandler(object sender, CapUsageChangedEventArgs e);

        /// <summary>
        /// Changed Event handler. Raises when an app (or more) have their capability usage changed.
        /// </summary>
        public event CapUsageChangedEventHandler CapUsageChanged;

        /// <summary>
        /// Release all resources used by <see cref="CapUsageSnitcher"/>.
        /// </summary>
        public void Dispose()
        {
            StopSnitching();
            handle.Free();
        }

        private static IntPtr WnfSnitcher(ulong stateName, uint changeStamp, IntPtr typeId, IntPtr callbackContext, IntPtr bufferPtr, uint bufferSize)
        {
            var @this = (CapUsageSnitcher)GCHandle.FromIntPtr(callbackContext).Target;

            var pkgs = @this.SnitchPackages();

            List<CapSnitchApp> diffs = new List<CapSnitchApp>();
            for (int i = 0; i < pkgs.Count; i++)
            {
                bool found = false;
                for (int j = 0; j < @this.backstore.Count; j++)
                {
                    if (pkgs[i].AppName == @this.backstore[j].AppName)
                    {
                        found = true;
                        if (pkgs[i].IsInUse != @this.backstore[j].IsInUse)
                            diffs.Add(pkgs[i]);
                    }
                }

                if (!found)
                    diffs.Add(pkgs[i]);
            }

            // TODO: WHAT HAPPENS IF A PACKAGE IS REMOVED?
            // From my tests it works even if the package is being uninstalled while the app is accessing a capability.

            @this.backstore = pkgs;

            @this.CapUsageChanged?.Invoke(@this, new CapUsageChangedEventArgs { CapUsageChanged = diffs });
            return IntPtr.Zero;
        }
    }

    /// <summary>
    /// Changed event for CapUsageChanged.
    /// </summary>
    public class CapUsageChangedEventArgs : EventArgs
    {
        /// <summary>
        /// List of apps that have their capability usage changed since last listen.
        /// </summary>
        public List<CapSnitchApp> CapUsageChanged { get; set; }
    }
}
