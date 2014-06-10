using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class IClient
    {
        internal Connection Connection { get; set; }
        protected abstract void onClientConnect();
        protected abstract void onDisconnect(DisconnectReason Reason);
        protected abstract void onException(Exception ex, ErrorType errorType);
        protected abstract void Disconnect();

        public IClient()
        {

        }
    }
}