using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network
{
    public abstract class OperationSocket
    {
        public SSPClient Client { get; private set; }

        public OperationSocket(SSPClient Client)
        {
            this.Client = Client;
        }

        public virtual void onConnect() { }
        public virtual void onDisconnect() { }
        public virtual void onSend(byte[] Data, int Offset, int Length) { }
        public virtual void onReceive(byte[] Data, int Offset, int Length) { }

        public void Send(byte[] Data, int Offset, int Length)
        {
            onSend(Data, Offset, Length);
        }
    }
}