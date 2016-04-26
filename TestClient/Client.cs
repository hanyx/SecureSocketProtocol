using ExtraLayers.LZ4;
using ExtraLayers.LZMA;
using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.DataIntegrity;
using SecureSocketProtocol3.Security.Handshakes;
using SecureSocketProtocol3.Security.Layers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using TestClient.Sockets;

namespace TestClient
{
    public class Client : SSPClient
    {
        public Client()
            : base(new ClientProps())
        {

        }

        public override void onConnect()
        {
            //return;
            while (false)
            {
                using (TestSocket testSock2 = new TestSocket(this))
                {
                    testSock2.Connect();
                    testSock2.Disconnect();
                }
                //Thread.Sleep(5000);
            }

            TestSocket testSock = new TestSocket(this);
            testSock.Connect();

            Random rnd = new Random();
            Stopwatch RuntimeSW = Stopwatch.StartNew();
            Benchmark bench = new Benchmark();
            byte[] Data = new byte[65535];
            //rnd.NextBytes(Data);
            int PacketsSend = 0;
            int RealSend = 0;

            //endless test
            /**/while (true)
            {
                Data = new byte[rnd.Next(1, 65535)];
                bench.Bench(new BenchCallback(() => RealSend += testSock.Send_Protobuf_Message(Data)));
                PacketsSend++;

                if (bench.PastASecond)
                {
                    ulong Speed = bench.SpeedPerSec * (ulong)Data.Length;
                    double MegaByteSpeed = Math.Round(((double)Speed / 1000F) / 1000F, 2);
                    double GigabitSpeed = Math.Round((MegaByteSpeed / 1000F) * 8, 2);

                    double SendMegaByteSpeed = Math.Round(((double)RealSend / 1000F) / 1000F, 2);
                    RealSend = 0;

                    Console.WriteLine("Messages Send: " + PacketsSend + "\t\tThroughput:" + SendMegaByteSpeed + "MBps\t\t" + GigabitSpeed + "Gbps");
                    Console.Title = "SSP Client - Running for " + RuntimeSW.Elapsed.Hours + ":" + RuntimeSW.Elapsed.Minutes + ":" + RuntimeSW.Elapsed.Seconds;
                }
            }


            Console.WriteLine("============= Protobuf Performance =============");
            PacketsSend = 0;
            RuntimeSW = Stopwatch.StartNew();
            bench = new Benchmark();
            while (RuntimeSW.Elapsed.Seconds <= 1)
            {
                PacketsSend++;
                bench.Bench(new BenchCallback(() => testSock.Send_Protobuf_Message(Data)));

                if (bench.PastASecond)
                {
                    ulong Speed = bench.SpeedPerSec * (ulong)Data.Length;
                    double MegaByteSpeed = Math.Round(((double)Speed / 1000F) / 1000F, 2);
                    double GigabitSpeed = Math.Round((MegaByteSpeed / 1000F) * 8, 2);

                    Console.WriteLine("Packets Send: " + PacketsSend + "\t\t" + MegaByteSpeed + "MBps\t\t" + GigabitSpeed + "Gbps");
                    Console.Title = "SSP Client - Running for " + RuntimeSW.Elapsed.Hours + ":" + RuntimeSW.Elapsed.Minutes + ":" + RuntimeSW.Elapsed.Seconds;
                }
            }


            Console.WriteLine("============= BinaryFormatter Performance =============");
            PacketsSend = 0;
            RuntimeSW = Stopwatch.StartNew();
            bench = new Benchmark();
            while (RuntimeSW.Elapsed.Seconds <= 10)
            {
                PacketsSend++;
                bench.Bench(new BenchCallback(() => testSock.Send_BinaryFormatter_Message(Data)));

                if (bench.PastASecond)
                {
                    ulong Speed = bench.SpeedPerSec * (ulong)Data.Length;
                    double MegaByteSpeed = Math.Round(((double)Speed / 1000F) / 1000F, 2);
                    double GigabitSpeed = Math.Round((MegaByteSpeed / 1000F) * 8, 2);

                    Console.WriteLine("Packets Send: " + PacketsSend + "\t\t" + MegaByteSpeed + "MBps\t\t" + GigabitSpeed + "Gbps");
                    Console.Title = "SSP Client - Running for " + RuntimeSW.Elapsed.Hours + ":" + RuntimeSW.Elapsed.Minutes + ":" + RuntimeSW.Elapsed.Seconds;
                }
            }
        }

        private void onBenchEvent()
        {
            int number = base.GetNextRandomInteger();
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

        public override void onOperationalSocket_Connected(OperationalSocket OPSocket)
        {

        }

        public override void onOperationalSocket_BeforeConnect(OperationalSocket OPSocket)
        {

        }

        public override void onOperationalSocket_Disconnected(OperationalSocket OPSocket, DisconnectReason Reason)
        {

        }

        public override void onApplyLayers(LayerSystem layerSystem)
        {
            for (int i = 0; i < 1; i++)
            {
                //layerSystem.AddLayer(new Lz4Layer());
                //layerSystem.AddLayer(new LzmaLayer());
                //layerSystem.AddLayer(new QuickLzLayer());
                layerSystem.AddLayer(new AesLayer(base.Connection));
                //layerSystem.AddLayer(new WopExLayer(5, 1, false, this));
                //layerSystem.AddLayer(new TwoFishLayer(base.Connection));
                //layerSystem.AddLayer(new RC4Layer());
                ///layerSystem.AddLayer(new XmlHidingLayer());
            }
        }

        private IDataIntegrityLayer _dataIntegrityLayer;
        public override IDataIntegrityLayer DataIntegrityLayer
        {
            get
            {
                //return new CRC32Layer();
                if (_dataIntegrityLayer == null)
                    _dataIntegrityLayer = new HMacLayer(this);
                return _dataIntegrityLayer;
            }
        }

        public override void onApplyHandshakes(HandshakeSystem handshakeSystem)
        {
            SimpleRsaHandshake simpleRsaHandshake = new SimpleRsaHandshake(this);
            simpleRsaHandshake.onVerifyFingerPrint += simpleRsaHandshake_onVerifyFingerPrint;
            handshakeSystem.AddLayer(simpleRsaHandshake);



            List<MemoryStream> keys = new List<MemoryStream>();
            keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey1.dat")));
            keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey2.dat")));
            Stream PublicKeyFile = new MemoryStream(File.ReadAllBytes(@".\Data\PublicKey1.dat"));

            //handshakeSystem.AddLayer(new MazeHandshake(this, new System.Drawing.Size(128, 128), 5, 1, "UserTest", "PassTest",
            //                         keys.ToArray(), PublicKeyFile));

            //handshakeSystem.AddLayer(new SslHandshake(this));
        }

        bool simpleRsaHandshake_onVerifyFingerPrint(byte[] PublicKey, string FingerPrint, string Sha512FingerPrint)
        {
            //Console.WriteLine("Host MD5 FingerPrint: " + FingerPrint + "\r\n     SHA512: " + Sha512FingerPrint + "\r\n");

            if (FingerPrint != "49:17:B6:AD:D9:FA:C4:09:B3:C7:4E:9E:02:D6:97:74" || Sha512FingerPrint != "BD:7C:94:E5:90:B2:04:E9:06:7A:95:8E:9C:EC:75:9E:CD:39:69:E4:A9:FC:9A:E4:1A:E2:1A:7B:4C:23:C4:19:43:13:64:E2:5C:C4:49:4B:45:AF:C4:85:81:29:F1:B7:3B:57:FD:D5:50:67:43:30:C9:26:D0:CE:8C:6C:BA:9B")
            {
                Console.Write("FingerPrint changed!! still want to continue (no) ?");

                if (Console.ReadLine() == "no")
                    return false;
            }

            return true;
        }
    }
}
