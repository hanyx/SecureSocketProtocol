using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    internal class MsgOpDisconnectResponse : IMessage
    {
        [ProtoMember(1)]
        public ushort ConnectionId { get; set; }
        
        public MsgOpDisconnectResponse()
            : base()
        {

        }
        public MsgOpDisconnectResponse(ushort ConnectionId)
            : base()
        {
            this.ConnectionId = ConnectionId;
        }

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {
            RequestHeader reqHeader = Header as RequestHeader;
            if (reqHeader != null)
            {
                reqHeader.HandleResponse(client, this);
            }
        }
    }
}