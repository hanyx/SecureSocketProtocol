using SecureSocketProtocol3.Network.Messages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.Serialization
{
    public interface ISerialization
    {
        byte[] Serialize(IMessage Message);
        IMessage Deserialize(byte[] MessageData, int Offset, int Length, Type MessageType);
    }
}