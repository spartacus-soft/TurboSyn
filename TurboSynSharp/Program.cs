using System;
using System.Threading.Tasks;

namespace TurboSynSharp
{
    sealed class Program
    {
        static async Task Main(string[] args)
        {
            if (OperatingSystem.IsWindows())
            {
                const string content = "209.85.128.0/17";
                var results = TurboSyn.ScanAsync(content, 443, progress =>
                {
                    Console.Title = progress.ToString();
                });

                await foreach (var address in results)
                {
                    Console.WriteLine(address);
                }
            }

            Console.WriteLine("TurboSynSharp!");
        }
    }
}
