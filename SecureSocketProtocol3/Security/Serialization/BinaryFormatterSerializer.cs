using SecureSocketProtocol3.Network.Messages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;

namespace SecureSocketProtocol3.Security.Serialization
{
    public sealed class BinaryFormatterSerializer : ISerialization
    {
        public byte[] Serialize(IMessage Message)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                BinaryFormatter bf = new BinaryFormatter();
                bf.Binder = new DeserializationBinder();
                bf.Serialize(stream, Message);
                return stream.ToArray();
            }
        }

        public IMessage Deserialize(byte[] MessageData, int Offset, int Length, Type MessageType)
        {
            using (MemoryStream stream = new MemoryStream(MessageData, Offset, Length))
            {
                BinaryFormatter bf = new BinaryFormatter();
                bf.Binder = new DeserializationBinder();
                return bf.Deserialize(stream) as IMessage;
            }
        }


        sealed class DeserializationBinder : SerializationBinder
        {
            public override Type BindToType(string assemblyName, string typeName)
            {
                Type typeToDeserialize = null;

                // For each assemblyName/typeName that you want to deserialize to
                // a different type, set typeToDeserialize to the desired type.
                String exeAssembly = Assembly.GetExecutingAssembly().FullName;

                // The following line of code returns the type.
                typeToDeserialize = Type.GetType(String.Format("{0}, {1}", typeName, exeAssembly));

                return typeToDeserialize;
            }
        }
    }
}