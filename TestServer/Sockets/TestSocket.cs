using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;
using TestServer.Sockets.Headers;

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
        public override void onReceiveData(byte[] Data, Header header)
        {
            bench.Bench(new BenchCallback(() => { }));

            if (bench.PastASecond)
            {
                Console.WriteLine("Speed:" + bench.SpeedPerSec + ", raw size: " + Math.Round( ((((ulong)(Data.Length + 28) * bench.SpeedPerSec) / 1000F) / 1000F) / 1000F, 2)    + "GBps");
            }
        }

        public override void onReceiveMessage(IMessage Message, Header header)
        {

        }

        public override void onBeforeConnect()
        {
            base.Headers.RegisterHeader(typeof(TestHeader));
        }

        public override void onConnect()
        {

        }

        public override void onDisconnect(DisconnectReason Reason)
        {

        }

        public override void onException(Exception ex, ErrorType errorType)
        {

        }
    }
}
