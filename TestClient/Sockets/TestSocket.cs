using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
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

        public override void onReceiveData(byte[] Data, Header header)
        {

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

        public void SendStuff()
        {
            base.SendData(new byte[70000], 0, 70000, new TestHeader());
        }
    }
}