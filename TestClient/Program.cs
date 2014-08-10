using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.IO;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Encryptions;
using System.Threading;
using SecureSocketProtocol3.Utils;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.MazingHandshake;

namespace TestClient
{
    class Program
    {
        static void Main(string[] args)
        {

            Client client = new Client();
            /*Random random = new Random();

            byte[] temp = new byte[70000];
            
            Stopwatch sw = Stopwatch.StartNew();
            Stopwatch RuntimeSW = Stopwatch.StartNew();

            client.CreateConnection();

            int count = 0;
            int speed = 0;
            int packets = 0;

            while (true)
            {
                temp = new byte[random.Next(5000000)];
                client.connection.Send(temp, 0, temp.Length, new SystemHeader());

                speed += temp.Length;
                packets++;

                if (sw.ElapsedMilliseconds >= 1000)
                {
                    Console.Title = "Runtime: " + RuntimeSW.Elapsed;

                    double SpeedPerSec = Math.Round(((speed / 1024F) / 1024F), 2);
                    Console.WriteLine("Speed:" + SpeedPerSec + "MBps" + ", " + Math.Round(((SpeedPerSec / 1024F) * 8), 2) + "Gbps, Packets: " + packets + ", last size:" + temp.Length);
                    speed = 0;
                    packets = 0;
                    sw = Stopwatch.StartNew();
                }
            }*/
            Process.GetCurrentProcess().WaitForExit();
        }
    }

    public class Client : SSPClient
    {
        public Client()
            : base(new ClientProps())
        {

        }

        protected override void onClientConnect()
        {

        }

        protected override void onDisconnect(DisconnectReason Reason)
        {

        }

        private class ClientProps : ClientProperties
        {

            public override string HostIp
            {
                get { return "127.0.0.1"; }
            }

            public override ushort Port
            {
                get { return 444; }
            }

            public override int ConnectionTimeout
            {
                get { return 30000; }
            }

            public override byte[] PrivateKey
            {
                get
                {
                    return new byte[]
                    {
                        80, 118, 131, 114, 195, 224, 157, 246, 141, 113,
                        186, 243, 77, 151, 247, 84, 70, 172, 112, 115,
                        112, 110, 91, 212, 159, 147, 180, 188, 143, 251,
                        218, 155
                    };
                }
            }

            public override string Username
            {
                get { return ""; }
            }

            public override string Password
            {
                get { return ""; }
            }

            public override Stream[] KeyFiles
            {
                get { return new Stream[0]; }
            }
        }
    }
}