using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    public class MsgCreateConnectionResponse : IMessage
    {
        [ProtoMember(1)]
        public ushort ConnectionId;

        [ProtoMember(2)]
        public bool Success;

        public MsgCreateConnectionResponse(ushort ConnectionId, bool Success)
            : base()
        {
            this.ConnectionId = ConnectionId;
            this.Success = Success;
        }

        public MsgCreateConnectionResponse()
            : base()
        {

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