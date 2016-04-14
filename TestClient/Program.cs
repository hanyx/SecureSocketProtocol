using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.IO;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.Encryptions;
using System.Threading;
using SecureSocketProtocol3.Utils;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.MazingHandshake;
using TestClient.Sockets;
using SecureSocketProtocol3.Security.Layers;
using SecureSocketProtocol3.Security.DataIntegrity;
using ExtraLayers.LZMA;
using ExtraLayers.LZ4;
using SecureSocketProtocol3.Security.Handshakes;

namespace TestClient
{
    class Program
    {
        static void Main(string[] args)
        {
            /*RandomDecimal rndDecimal = new RandomDecimal();
            SecureRandom rnd = new SecureRandom();

            while (true)
            {
                var num = rnd.NextLong(5, 100);

                if (num < 5)
                {

                }

                Console.WriteLine(num);
            }*/
            //SysLogger.onSysLog += SysLogger_onSysLog;
            Console.Title = "SSP Client";
                    Random rnd = new Random();

            for (int i = 0; i < 5; i++)
            {
                new Thread(new ThreadStart(() =>
                {
                    int Id = rnd.Next(0, 100);
                    while (true)
                    {
                        Console.WriteLine("[" + Id + "]Connecting..");
                        Client client = new Client();
                    }
                })).Start();
            }
            Process.GetCurrentProcess().WaitForExit();
        }

        static void SysLogger_onSysLog(string Message, SysLogType Type)
        {
            Console.WriteLine("[SysLogger][" + Type + "] " + Message);
        }
    }
}