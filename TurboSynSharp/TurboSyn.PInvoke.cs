using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace TurboSynSharp
{
    partial class TurboSyn
    {
        private enum TurboSynScanState
        {
            Success = 0,
            Cancelled = 1,
            Completed = 2,
        }

        private struct TurboSynScanResult
        {
            public TurboSynScanState State;
            public int Port;
            public int IPLength;
            public Byte16 IPAddress;
            public ReadOnlySpan<byte> IPAddressByteSpan => MemoryMarshal.CreateReadOnlySpan(ref IPAddress.Element0, IPLength);
        }

        private struct TurboSynScanProgress
        {
            public ulong CurrentCount;
            public ulong TotalCount;
            public int IPLength;
            public Byte16 IPAddress;
            public ReadOnlySpan<byte> IPAddressByteSpan => MemoryMarshal.CreateReadOnlySpan(ref IPAddress.Element0, IPLength);
        }

        [InlineArray(16)]
        private struct Byte16
        {
            public byte Element0;
        }


        private const string TurboSynLib = "TurboSyn.dll";

        [LibraryImport(TurboSynLib, SetLastError = true)]
        private static partial nint TurboSynCreateScanner(
            nint content);

        [LibraryImport(TurboSynLib, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool TurboSynStartScan(
            nint scanner,
            int port,
            delegate* unmanaged[Cdecl]<TurboSynScanResult, nint, void> resultCallback,
            delegate* unmanaged[Cdecl]<TurboSynScanProgress, nint, void> progressCallback,
            nint userParam);

        [LibraryImport(TurboSynLib, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool TurboSynCancelScan(
            nint scanner);

        [LibraryImport(TurboSynLib, SetLastError = true)]
        private static partial void TurboSynFreeScanner(
            nint scanner);
    }
}
