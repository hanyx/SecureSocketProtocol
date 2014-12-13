using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    public class MsgGetNextIdResponse : IMessage
    {
        [ProtoMember(1)]
        public decimal Number;

        public MsgGetNextIdResponse(decimal Number)
            : base()
        {
            this.Number = Number;
        }

        public MsgGetNextIdResponse()
            : base()
        {

        }

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {
            RequestHeader reqHeader = Header as RequestHeader;
            if (reqHeader != null)
            {
                reqHeader.HandleResponse(client, Number);
            }
        }
    }
}
