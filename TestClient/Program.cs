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
using TestClient.Sockets;

namespace TestClient
{
    class Program
    {
        static void Main(string[] args)
        {

            /*byte[] TestKey = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] TestSalt  = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] TestIV = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 2, 2, 2, 2, 3, 3, 3, 3 };

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(123456, 15, ref encCode, ref decCode);

            WopEx wopEx = new WopEx(TestKey, TestSalt, TestIV, encCode, decCode, SecureSocketProtocol3.WopEncMode.Simple, 1);
            */





            SysLogger.onSysLog += SysLogger_onSysLog;
            Console.Title = "SSP Client";
            try
            {
                Client client = new Client();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            Random random = new Random();

            byte[] temp = new byte[70000];
            
            Stopwatch sw = Stopwatch.StartNew();
            Stopwatch RuntimeSW = Stopwatch.StartNew();

            /*client.CreateConnection();

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

        static void SysLogger_onSysLog(string Message, SysLogType Type)
        {
            Console.WriteLine("[SysLogger][" + Type + "] " + Message);
        }
    }

    public class Client : SSPClient
    {
        public Client()
            : base(new ClientProps())
        {

        }

        public override void onConnect()
        {
            Console.WriteLine("Client successfully connected");


            /*Benchmark bench = new Benchmark();
            while (true)
            {
                bench.Bench(new BenchCallback(onBenchEvent));
                
                if(bench.PastASecond)
                {
                    Console.WriteLine("Speed:" + bench.SpeedPerSec);
                }
            }*/

            TestSocket testSock = new TestSocket(this);
            testSock.Connect();

            Stopwatch RuntimeSW = Stopwatch.StartNew();

            Benchmark bench = new Benchmark();
            //while (false)
            {
                //Thread.Sleep(1);
                int size = 0;
                bench.Bench(new BenchCallback(() => size = testSock.SendStuff()));

                if (bench.PastASecond)
                {
                    ulong Speed = bench.SpeedPerSec * 60000;
                    double MegaByteSpeed = Math.Round(((double)Speed / 1000F) / 1000F, 2);
                    double GigabitSpeed = Math.Round((MegaByteSpeed / 1000F) * 8, 0);

                    Console.WriteLine("Speed:" + bench.SpeedPerSec + "(" + size + ")\t\t" + MegaByteSpeed + "MBps\t\t" + GigabitSpeed + "Gbps");
                    Console.Title = "SSP Client - Running for " + RuntimeSW.Elapsed.Hours + ":" + RuntimeSW.Elapsed.Minutes + ":" + RuntimeSW.Elapsed.Seconds;
                }
            }
        }

        private void onBenchEvent()
        {
            int number = base.Connection.GetNextRandomInteger();
        }

        public override void onDisconnect(DisconnectReason Reason)
        {

        }

        public override void onException(Exception ex, ErrorType errorType)
        {

        }

        public override void onBeforeConnect()
        {
            base.RegisterOperationalSocket(new TestSocket(this));
        }

        private class ClientProps : ClientProperties
        {

            public override string HostIp
            {
                get { return "127.0.0.1"; }// "192.168.2.10"; }
            }

            public override ushort Port
            {
                get { return 444; }
            }

            public override int ConnectionTimeout
            {
                get { return 30000; }
            }

            public override string Username
            {
                get { return "UserTest"; }
            }

            public override string Password
            {
                get { return "PassTest"; }
            }

            public override Stream[] PrivateKeyFiles
            {
                get
                {
                    List<MemoryStream> keys = new List<MemoryStream>();
                    keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey1.dat")));
                    keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey2.dat")));
                    return keys.ToArray();
                }
            }

            public override Stream PublicKeyFile
            {
                get
                {
                    return new MemoryStream(File.ReadAllBytes(@".\Data\PublicKey1.dat"));
                }
            }

            public override byte[] NetworkKey
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

            public override uint Cipher_Rounds
            {
                get { return 512; }
            }
        }
    }
}