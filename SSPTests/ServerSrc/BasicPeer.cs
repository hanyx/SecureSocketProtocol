using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SSPTests.ServerSrc
{
    public class BasicPeer : SSPClient
    {
        public BasicPeer()
            : base()
        {

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

        public override void onBeforeConnect()
        {

        }
    }
}