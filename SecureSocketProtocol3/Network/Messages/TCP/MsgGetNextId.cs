using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    internal class MsgGetNextId : IMessage
    {
        public MsgGetNextId()
            : base()
        {

        }

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {
            RequestHeader ReqHeader = Header as RequestHeader;
            if (ReqHeader != null)
            {
                if (client.IsServerSided)
                {
                    client.Connection.SendMessage(new MsgGetNextIdResponse(client.Server.randomDecimal.NextDecimal()), new RequestHeader(ReqHeader.RequestId, true));
                }
            }
        }
    }
}