using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SnitchCap
{
    public struct CapSnitchApp
    {
        public string AppName;
        public string CapabilityName;
        public bool IsPackaged;
        public bool IsInUse;
    }

    public class CapUsageSnitcher : IDisposable
    {
        [DllImport("combase.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int RoGetActivationFactory(
            [MarshalAs(UnmanagedType.HString)] string activatableClassId,
            [In] ref Guid iid,
            [Out, MarshalAs(UnmanagedType.IInspectable)] out object factory);

        [ComImport, Guid("42947746-4ea0-48c2-9274-062ed61f8daa"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        internal interface ICapabilityUsageStatics
        {
            ICapabilityUsage Create([MarshalAs(UnmanagedType.HString)] string capabilityName);
        }

        [ComImport, Guid("a19979e0-a2c3-4a21-8610-a6d893ba4f86"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
        internal interface ICapabilityUsage
        {
            void CreateSession();
            void CreatePackagedSession();
            void GetUsage();
            void GetUsageForNonPackagedClient();
            object GetUsageForNonPackagedClients([MarshalAs(UnmanagedType.HString)] string capabilityName);
            ulong GetWNFStateNameForChanges();
        }

        ICapabilityUsageStatics statics;
        ICapabilityUsage usage;

        IntPtr subscription;
        GCHandle handle;
        ulong wnf;
        string capToSnitch;
        List<CapSnitchApp> backstore;

        public delegate void CapUsageChangedEventHandler(object sender, CapUsageChangedEventArgs e);

        public CapUsageSnitcher(string capabilityName)
        {
            capToSnitch = capabilityName;

            Guid guidCapUsageStatics = typeof(ICapabilityUsageStatics).GUID;
            RoGetActivationFactory("Windows.Internal.CapabilityAccess.Management.CapabilityUsage", ref guidCapUsageStatics, out object fact);
            statics = (ICapabilityUsageStatics)fact;

            usage = statics.Create(capToSnitch);
            wnf = usage.GetWNFStateNameForChanges();
            backstore = SnitchPackages();
            handle = GCHandle.Alloc(this);
        }

        public void StartSnitching()
        {
            var wnfStateData = WnfInterop.QueryWnf(wnf);
            subscription = WnfInterop.SubscribeWnf(wnf, WnfSnitcher, GCHandle.ToIntPtr(handle), wnfStateData.Changestamp);
        }

        public void StopSnitching()
        {
            throw new NotImplementedException();
        }

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
            catch (Exception)
            {

                throw;
            }

            return packageIsAccessingCapRightNow;
        }

        public static IntPtr WnfSnitcher(ulong stateName, uint changeStamp, IntPtr typeId, IntPtr callbackContext, IntPtr bufferPtr, uint bufferSize)
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

            //TODO: IF PACKAGE IS REMOVED!

            @this.backstore = pkgs;

            @this.CapUsageChanged?.Invoke(@this, new CapUsageChangedEventArgs { CapUsageChanged = diffs });
            return IntPtr.Zero;
        }

        public event CapUsageChangedEventHandler CapUsageChanged;

        public void Dispose()
        {
            //unsubscribe wnf IMPORTANT

            handle.Free();
        }
    }

    public class CapUsageChangedEventArgs : EventArgs
    {
        public List<CapSnitchApp> CapUsageChanged { get; set; }
    }
}
