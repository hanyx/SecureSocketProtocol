using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using TestLib.Messages;
using TestServer.Sockets.Headers;
using TestServer.Sockets.Messages;

namespace TestServer.Sockets
{
    public class TestSocket : OperationalSocket
    {
        public override string Name
        {
            get { return "Testsocket"; }
        }

        public override Version Version
        {
            get { return new Version(1, 0, 0, 1); }
        }

        public TestSocket(SSPClient client)
            : base(client)
        {

        }

        Benchmark bench = new Benchmark();
        /*public override void onReceiveData(byte[] Data, Header header)
        {
            bench.Bench(new BenchCallback(() => { }));

            if (bench.PastASecond)
            {
                Console.WriteLine("Speed:" + bench.SpeedPerSec + ", raw size: " + Math.Round( ((((ulong)(Data.Length + 28) * bench.SpeedPerSec) / 1000F) / 1000F) / 1000F, 2)    + "GBps");
            }
        }*/

        Stopwatch sw = Stopwatch.StartNew();
        long ReceivePerSec = 0;
        long DecompressedSizePerSec = 0;
        long MessagesReceived = 0;

        public override void onReceiveMessage(IMessage Message, Header header)
        {
            MessagesReceived++;
            ReceivePerSec += Message.RawSize;
            DecompressedSizePerSec += Message.DecompressedRawSize;

            if (sw.ElapsedMilliseconds >= 1000)
            {
                double SpeedThroughputPerSec = Math.Round(((double)ReceivePerSec / 1000F) / 1000F, 2);
                double DecompressedSpeedPerSec = Math.Round(((double)DecompressedSizePerSec / 1000F) / 1000F, 2);
                Console.WriteLine("Messages /sec: " + MessagesReceived + "\tThroughput:" + SpeedThroughputPerSec + "MBps\tDecompressed speed: " + DecompressedSpeedPerSec + "MBps");
                sw = Stopwatch.StartNew();
                ReceivePerSec = 0;
                DecompressedSizePerSec = 0;
                MessagesReceived = 0;
            }

            //base.SendMessage(new TestMessage() { Buffer = new byte[] { 1, 3, 3, 7 } }, header);
        }

        public override void onBeforeConnect()
        {
            base.Headers.RegisterHeader(typeof(TestHeader));
            base.MessageHandler.AddMessage(typeof(TestMessage), "TEST_MESSAGE");
            base.MessageHandler.AddMessage(typeof(BinaryFormatterTestMessage), "TEST_MESSAGE_BINARY_FORMATTER");
        }

        public override void onConnect()
        {
            //Console.WriteLine("Operational Socket is connected");
        }

        public override void onDisconnect(DisconnectReason Reason)
        {

        }

        public override void onException(Exception ex, ErrorType errorType)
        {

        }
    }
}
