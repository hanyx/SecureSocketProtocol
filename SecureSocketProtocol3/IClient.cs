using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class IClient
    {
        internal Connection Connection { get; set; }
        public abstract void onClientConnect();
        public abstract void onDisconnect(DisconnectReason Reason);
        public abstract void onException(Exception ex, ErrorType errorType);
        public abstract void Disconnect();

        public IClient()
        {

        }
    }
}