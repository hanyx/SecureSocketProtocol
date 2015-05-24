using ProtoBuf;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    internal class MsgKeepAlive : IMessage
    {
        [ProtoMember(1)]
        public byte[] Payload { get; set; }

        public MsgKeepAlive()
            : base()
        {
            this.Payload = new byte[32];
            new FastRandom().NextBytes(this.Payload);
        }

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {

        }
    }
}