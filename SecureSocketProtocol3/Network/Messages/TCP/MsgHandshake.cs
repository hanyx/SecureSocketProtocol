using ProtoBuf;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    internal class MsgHandshake : IMessage
    {
        [ProtoMember(1)]
        public byte[] Data { get; set; }

        public MsgHandshake(byte[] Data)
            : base()
        {
            this.Data = Data;
        }
        public MsgHandshake()
            : base()
        {

        }

        public override void ProcessPayload(IClient client)
        {

        }
    }
}