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
            FastRandom fastRand = new FastRandom();
            this.Payload = new byte[fastRand.Next(32, 256)];
            fastRand.NextBytes(this.Payload);
        }

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {

        }
    }
}