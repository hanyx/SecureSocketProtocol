using Newtonsoft.Json;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtraLayers
{
    public class JSonSerializer : ISerialization
    {
        public byte[] Serialize(IMessage Message)
        {
            return ASCIIEncoding.UTF8.GetBytes(JsonConvert.SerializeObject(Message));
        }

        public IMessage Deserialize(byte[] MessageData, int Offset, int Length, Type MessageType)
        {
            return JsonConvert.DeserializeObject(ASCIIEncoding.UTF8.GetString(MessageData, Offset, Length), MessageType) as IMessage;
        }
    }
}
