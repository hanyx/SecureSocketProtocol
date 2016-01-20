using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

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

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {
            SSPClient _client = client as SSPClient;
            if (_client != null)
            {
                
            }
        }
    }
}