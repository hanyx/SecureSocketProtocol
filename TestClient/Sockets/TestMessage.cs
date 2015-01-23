using ProtoBuf;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace TestClient.Sockets
{
    [ProtoContract]
    public class TestMessage : IMessage
    {
        [ProtoMember(1)]
        public byte[] Buffer;

        [ProtoMember(2)]
        public string TestStr;

        public TestMessage()
            : base()
        {
            TestStr = "hadshusdauhdsauhsad";
        }

        public override void ProcessPayload(SecureSocketProtocol3.SSPClient client, OperationalSocket OpSocket)
        {

        }
    }
}
