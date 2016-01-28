using SecureSocketProtocol3;
using SecureSocketProtocol3.Attributes;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestClient.Sockets
{
    [Serializable]
    public class NetSerializeMessage : IMessage
    {
        public byte[] Buffer;
        public string StringTest;
        public byte ByteTest;
        public int IntTest;
        public uint UIntTest;
        public long LongTest;
        public ulong ULongTest;
        public decimal DecimalTest;
        public float FloatTest;

        public NetSerializeMessage()
            : base()
        {

        }

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {

        }

        public override ISerialization onGetSerializer()
        {
            return new ExtraLayers.NetSerializer.NetSerializer(new Type[] { typeof(NetSerializeMessage) });
        }
    }
}
