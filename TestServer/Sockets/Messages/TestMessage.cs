using ProtoBuf;
using SecureSocketProtocol3.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace TestServer.Sockets.Messages
{
    [ProtoContract]
    public class TestMessage : IMessage
    {
        [ProtoMember(1)]
        public byte[] Buffer;

        public TestMessage()
            : base()
        {

        }

        public override void ProcessPayload(SecureSocketProtocol3.SSPClient client)
        {

        }
    }
}