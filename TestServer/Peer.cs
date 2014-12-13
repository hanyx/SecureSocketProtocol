using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.Text;
using TestServer.Sockets;

namespace TestServer
{
    public class Peer : SSPClient
    {
        public Peer()
            : base()
        {

        }


        public override void onConnect()
        {
            Console.WriteLine("User \"" + base.Username + "\" connected, Peer connected " + base.RemoteIp);
            //TestSocket testSock = new TestSocket(this);
            //testSock.Connect();
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
    }
}
