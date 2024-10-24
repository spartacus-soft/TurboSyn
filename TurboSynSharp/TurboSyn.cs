using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Channels;

namespace TurboSynSharp
{
    /// <summary>
    /// TurboSync扫描
    /// </summary>   
    public static partial class TurboSyn
    {
        /// <summary>
        /// 扫描进度
        /// </summary>
        /// <param name="CurrentCount">当前数量</param>
        /// <param name="TotalCount">总数量</param>
        /// <param name="IPAddress">当前扫描的IP地址</param>
        public record struct ScanProgress(ulong CurrentCount, ulong TotalCount, IPAddress IPAddress);
        private record UserParam(ChannelWriter<IPAddress> ChannelWriter, Action<ScanProgress>? ProgressChanged);

        /// <summary>
        /// 异步扫描
        /// </summary>
        /// <param name="content">CIDR或IP内容，一行一条记录</param>
        /// <param name="port">扫描的TCP端口</param>
        /// <param name="progressChanged">进度变化委托</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns></returns>
        /// <exception cref="Win32Exception"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        [SupportedOSPlatform("windows")]
        public static async IAsyncEnumerable<IPAddress> ScanAsync(
            string? content,
            int port,
            Action<ScanProgress>? progressChanged = default,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(port, 0);

            var hContent = Marshal.StringToHGlobalAnsi(content);
            var hScanner = TurboSynCreateScanner(hContent);
            if (hScanner <= nint.Zero)
            {
                Marshal.FreeHGlobal(hContent);
                throw new Win32Exception();
            }

            var channel = Channel.CreateUnbounded<IPAddress>();
            var userParam = new UserParam(channel.Writer, progressChanged);
            var userParamGCHandle = GCHandle.Alloc(userParam);

            try
            {
                var results = ScanAsync(hScanner, port, channel.Reader, userParamGCHandle, cancellationToken);
                await foreach (var address in results)
                {
                    yield return address;
                }
            }
            finally
            {
                userParamGCHandle.Free();
                Marshal.FreeHGlobal(hContent);
                TurboSynFreeScanner(hScanner);
            }
        }

        private static async IAsyncEnumerable<IPAddress> ScanAsync(
            nint hScanner,
            int port,
            ChannelReader<IPAddress> channelReader,
            GCHandle userParamGCHandle,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            using (cancellationToken.Register(() => TurboSynCancelScan(hScanner)))
            {
                UnsafeTurboSynStartScan();
                await foreach (var address in channelReader.ReadAllAsync(cancellationToken))
                {
                    yield return address;
                }
            }

            unsafe void UnsafeTurboSynStartScan()
            {
                var userParam = GCHandle.ToIntPtr(userParamGCHandle);
                TurboSynStartScan(hScanner, port, &OnResult, &OnProgress, userParam);
            }
        }

        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static void OnResult(TurboSynScanResult result, nint param)
        {
            var userParamGCHandle = GCHandle.FromIntPtr(param);
            if (userParamGCHandle.Target is UserParam userParam)
            {
                if (result.State == TurboSynScanState.Success)
                {
                    var address = new IPAddress(result.IPAddressByteSpan);
                    userParam.ChannelWriter.TryWrite(address);
                }
                else if (result.State == TurboSynScanState.Cancelled)
                {
                    userParam.ChannelWriter.Complete(new OperationCanceledException());
                }
                else
                {
                    userParam.ChannelWriter.Complete();
                }
            }
        }

        [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
        private static void OnProgress(TurboSynScanProgress progress, nint param)
        {
            var userParamGCHandle = GCHandle.FromIntPtr(param);
            if (userParamGCHandle.Target is UserParam userParam && userParam.ProgressChanged != null)
            {
                var address = new IPAddress(progress.IPAddressByteSpan);
                var scanProgress = new ScanProgress(progress.CurrentCount, progress.TotalCount, address);
                userParam.ProgressChanged(scanProgress);
            }
        }
    }
}
