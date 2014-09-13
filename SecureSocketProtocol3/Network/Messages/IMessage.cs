using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages
{
    public abstract class IMessage
    {
        /// <summary> This is the message in raw size we received </summary>
        public int RawSize { get; set; }

        /// <summary> This is the message in raw size after decompression </summary>
        public int DecompressedRawSize { get; set; }

        public Header Header { get; internal set; }

        public IMessage()
        {

        }

        public abstract void ProcessPayload(SSPClient client);

        public static byte[] Serialize(IMessage message)
        {
            using (MemoryStream ms = new MemoryStream())
            using (PayloadWriter pw = new PayloadWriter())
            {
                Serializer.Serialize(ms, message);

                pw.WriteThreeByteInteger((int)ms.Length);
                pw.WriteBytes(ms.ToArray());
                return pw.ToByteArray();
            }
        }

        public static IMessage DeSerialize(Type HeaderType, PayloadReader pr)
        {
            int size = pr.ReadThreeByteInteger();
            //byte[] data = pr.ReadBytes(size);
            IMessage message = (IMessage)Serializer.Deserialize(new MemoryStream(pr.Buffer, pr.Offset, size), HeaderType);
            pr.Offset += size;
            return message;
        }
    }
}
