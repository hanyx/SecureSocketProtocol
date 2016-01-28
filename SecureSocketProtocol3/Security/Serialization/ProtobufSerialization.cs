using ProtoBuf;
using SecureSocketProtocol3.Network.Messages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.Serialization
{
    public class ProtobufSerialization : ISerialization
    {
        public byte[] Serialize(Network.Messages.IMessage Message)
        {
            using (MemoryStream TempStream = new MemoryStream())
            {
                Serializer.Serialize(TempStream, Message);
                return TempStream.ToArray();
            }
        }

        public Network.Messages.IMessage Deserialize(byte[] MessageData, int Offset, int Length, Type MessageType)
        {
            return (IMessage)Serializer.Deserialize(new MemoryStream(MessageData, Offset, Length), MessageType);
        }
    }
}
