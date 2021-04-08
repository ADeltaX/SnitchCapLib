using System;
using System.Runtime.InteropServices;

namespace SnitchCap
{
    public class WnfInterop
    {
        public static int UpdateWnf(ulong state, byte[] data)
        {
            using (var buffer = data.ToBuffer())
            {
                ulong state_name = state;

                return ZwUpdateWnfStateData(ref state_name, buffer,
                    buffer.Length, null, IntPtr.Zero, 0, false);
            }
        }

        public static WnfStateData QueryWnf(ulong state)
        {
            var data = new WnfStateData();
            int tries = 10;
            int size = 4096;
            while (tries-- > 0)
            {
                using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(size))
                {
                    int status;
                    status = ZwQueryWnfStateData(ref state, null, IntPtr.Zero, out uint changestamp, buffer, ref size);

                    if (status == 0xC0000023)
                        continue;
                    buffer.SetLength(size);
                    data = new WnfStateData(changestamp, buffer.ReadBytes(size));
                }
            }
            return data;
        }

        public static IntPtr SubscribeWnf(ulong state, WnfUserCallback callback, IntPtr callbackContext, uint changeStamp = 0)
        {
            RtlSubscribeWnfStateChangeNotification(out IntPtr sub, state, changeStamp,
                callback, callbackContext, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            return sub;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class WnfType
        {
            public Guid TypeId;
        }

        public class WnfStateData
        {
            public uint Changestamp { get; }
            public byte[] Data { get; }

            public WnfStateData() { }
            public WnfStateData(uint changestamp, byte[] data)
            {
                Changestamp = changestamp;
                Data = data;
            }
        }

        [DllImport("ntdll.dll")]
        private static extern int ZwUpdateWnfStateData(
            ref ulong StateId,
            SafeBuffer DataBuffer,
            int DataBufferSize,
            [In, Optional] WnfType TypeId,
            [Optional] IntPtr Scope,
            int MatchingChangestamp,
            [MarshalAs(UnmanagedType.Bool)] bool CheckChangestamp
        );

        [DllImport("ntdll.dll")]
        private static extern int ZwQueryWnfStateData(
            ref ulong StateId,
            [In, Optional] WnfType TypeId,
            [Optional] IntPtr Scope,
            out uint Changestamp,
            SafeBuffer DataBuffer,
            ref int DataBufferSize
        );

        public delegate int WnfCallback(ulong StateName, int ChangeStamp, WnfType TypeId, IntPtr CallbackContext, SafeBuffer Buffer, int BufferSize);

        [DllImport("ntdll.dll")]
        private static extern int RtlSubscribeWnfStateChangeNotification(
                                    out IntPtr Subscription,
                                    ulong StateName,
                                    uint ChangeStamp,
                                    WnfUserCallback Callback,
                                    IntPtr CallbackContext,
                                    IntPtr TypeId,
                                    IntPtr Buffer,
                                    IntPtr Unknown
                                    );

        public delegate IntPtr WnfUserCallback(
            ulong StateName,
            uint ChangeStamp,
            IntPtr TypeId,
            IntPtr CallbackContext,
            IntPtr Buffer,
            uint BufferSize);

        public static IntPtr WnfSubscriptionLogHandler(ulong stateName, uint changeStamp, IntPtr typeId, IntPtr callbackContext, IntPtr bufferPtr, uint bufferSize)
        {
            Console.WriteLine("[" + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff") + "]");
            Console.WriteLine("State name: 0x{0:X}", stateName);
            Console.WriteLine("Change stamp: 0x{0:X}", changeStamp);
            Console.WriteLine("Buffer size: 0x{0:X} \n", bufferSize);
            byte[] buffer = new byte[bufferSize];
            Marshal.Copy(bufferPtr, buffer, 0, buffer.Length);
            if (bufferSize > 0)
                Console.WriteLine("Buffer content: " + BitConverter.ToString(buffer, 0).Replace('-', ' ') + "\n");
            return IntPtr.Zero;
        }


        // Original dev: James Forshaw @tyranid: Project Zero
        // Ref: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/46b95cba8f76fae9a5c8258d13057d5edfacdf90/NtApiDotNet/SafeHandles.cs
        public class SafeHGlobalBuffer : SafeBuffer
        {
            public SafeHGlobalBuffer(int length)
              : this(length, length) { }

            protected SafeHGlobalBuffer(int allocation_length, int total_length)
                : this(Marshal.AllocHGlobal(allocation_length), total_length, true) { }

            public SafeHGlobalBuffer(IntPtr buffer, int length, bool owns_handle)
              : base(owns_handle)
            {
                Length = length;
                Initialize((ulong)length);
                SetHandle(buffer);
            }

            public void SetLength(int length)
            {
                Length = length;
                Initialize((ulong)length);
            }

            public static SafeHGlobalBuffer Null { get { return new SafeHGlobalBuffer(IntPtr.Zero, 0, false); } }

            protected override bool ReleaseHandle()
            {
                if (!IsInvalid)
                {
                    Marshal.FreeHGlobal(handle);
                    handle = IntPtr.Zero;
                }
                return true;
            }

            public byte[] ReadBytes(ulong byte_offset, int count)
            {
                byte[] ret = new byte[count];
                ReadArray(byte_offset, ret, 0, count);
                return ret;
            }

            public byte[] ReadBytes(int count)
            {
                return ReadBytes(0, count);
            }

            public SafeHGlobalBuffer(byte[] data) : this(data.Length)
            {
                Marshal.Copy(data, 0, handle, data.Length);
            }

            public int Length
            {
                get; private set;
            }
        }
    }

    static class BufferUtils
    {
        public static WnfInterop.SafeHGlobalBuffer ToBuffer(this byte[] value)
        {
            return new WnfInterop.SafeHGlobalBuffer(value);
        }
    }
}
