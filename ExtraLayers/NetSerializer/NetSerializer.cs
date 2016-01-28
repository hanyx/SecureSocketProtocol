using NetSerializer;
using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtraLayers.NetSerializer
{
    public class NetSerializer : ISerialization
    {
        private Type[] SerializeTypes;
        private Serializer serializer;

        public NetSerializer(Type[] SerializeTypes)
        {
            this.SerializeTypes = SerializeTypes;
            this.serializer = new Serializer(SerializeTypes);
        }

        public byte[] Serialize(SecureSocketProtocol3.Network.Messages.IMessage Message)
        {
            using(MemoryStream ms = new MemoryStream())
            {
                serializer.Serialize(ms, Message);
                return ms.ToArray();
            }
        }

        public SecureSocketProtocol3.Network.Messages.IMessage Deserialize(byte[] MessageData, int Offset, int Length, Type MessageType)
        {
            return null;
        }
    }
}
