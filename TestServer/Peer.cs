using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.Text;

namespace TestServer
{
    public class Peer : SSPClient
    {
        public Peer()
            : base()
        {

        }


        public override void onClientConnect()
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
