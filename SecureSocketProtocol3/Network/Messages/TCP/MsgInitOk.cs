using ProtoBuf;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    public class MsgInitOk : IMessage
    {
        public MsgInitOk()
            : base()
        {

        }

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {
            client.Connection.InitSync.Value = true;
            client.Connection.InitSync.Pulse();
        }
    }
}