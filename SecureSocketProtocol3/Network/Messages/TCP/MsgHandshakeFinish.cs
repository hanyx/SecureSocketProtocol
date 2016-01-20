using ProtoBuf;
using SecureSocketProtocol3.Security.Handshakes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    internal class MsgHandshakeFinish : IMessage
    {
        public MsgHandshakeFinish()
            : base()
        {

        }

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {
            if (client != null && client.handshakeSystem != null)
            {
                Handshake curHandshake = client.handshakeSystem.GetCurrentHandshake();

                if (curHandshake != null)
                {
                    curHandshake.InternalFinish(false);
                }
            }
        }
    }
}