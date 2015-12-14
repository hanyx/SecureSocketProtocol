using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;
using TestClient.Sockets.Headers;

namespace TestClient.Sockets
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

        public override void onReceiveMessage(IMessage Message, Header header)
        {

        }

        public override void onBeforeConnect()
        {
            base.Headers.RegisterHeader(typeof(TestHeader));
            base.MessageHandler.AddMessage(typeof(TestMessage), "TEST_MESSAGE");
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

        string TestStr = "";

        private int test = 0;
        FastRandom rnd = new FastRandom();
        public byte[] testBytes;// = new byte[65000];
        public int SendStuff()
        {
            if (testBytes == null)
            {
                testBytes = new byte[65535];////rnd.Next(1, 6000)];
                rnd.NextBytes(testBytes);
            }

            //testBytes = new byte[25];
            test++;
            base.SendMessage(new TestMessage() { Buffer = testBytes }, new TestHeader());

            /*if (TestStr == "")
            {
                for (int i = 0; i < 10000; i++)
                    TestStr += "lol";
            }
            base.SendMessage(new TestMessage() { Buffer = ASCIIEncoding.ASCII.GetBytes(TestStr) }, new TestHeader());
            */
            return test;
        }

        public void TestBufferMessage(byte[] message)
        {
            base.SendMessage(new TestMessage() { Buffer = message }, new TestHeader());
        }
    }
}