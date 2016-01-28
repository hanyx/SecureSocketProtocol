using ExtraLayers;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestLib.Messages
{
    [Serializable]
    public class BinaryFormatterTestMessage : IMessage
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

        public BinaryFormatterTestMessage()
            : base()
        {
            
        }

        public override void ProcessPayload(SecureSocketProtocol3.SSPClient client, OperationalSocket OpSocket)
        {

        }

        public override ISerialization onGetSerializer()
        {
            return new BinaryFormatterSerializer();
        }
    }
}
