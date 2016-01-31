using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;
using TestClient.Sockets.Headers;
using TestLib.Messages;

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

        public void Send_BinaryFormatter_Message(byte[] Data)
        {
            base.SendMessage(new BinaryFormatterTestMessage() { /*DateTest = DateTime.Now.AddHours(2) Buffer = Data*/ }, new TestHeader());
        }

        public void Send_Protobuf_Message(byte[] Data)
        {
            TestMessage test = new TestMessage();
            //test.Buffer = Data;
            test.ListTest.Add(new TestO() { Num1 = 1337, Str1 = "kek it worked" });
            test.DateTest = DateTime.Now.AddHours(2);

            int k = base.SendMessage(test, new TestHeader());
        }
    }
}