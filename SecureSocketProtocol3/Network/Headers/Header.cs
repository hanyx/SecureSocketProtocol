using ProtoBuf;
using SecureSocketProtocol3.Hashers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace SecureSocketProtocol3.Network.Headers
{
    public abstract class Header
    {
        internal byte HeaderId;

        public abstract Version Version { get; }
        public abstract string HeaderName { get; }

        public Header()
        {

        }

        public ushort GetHeaderId()
        {
            CRC32 hasher = new CRC32();
            uint name = BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(HeaderName)), 0);
            uint version = BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(Version.ToString())), 0);
            return (ushort)(name * version);
        }

        public static byte[] Serialize(Header header)
        {
            using(MemoryStream ms = new MemoryStream())
            using(PayloadWriter pw = new PayloadWriter())
            {
                Serializer.Serialize(ms, header);
                pw.WriteUShort((ushort)ms.Length);
                pw.WriteBytes(ms.ToArray());
                return pw.ToByteArray();
            }
        }

        public static Header DeSerialize(Type HeaderType, PayloadReader pr)
        {
            ushort size = pr.ReadUShort();
            byte[] data = pr.ReadBytes(size);
            return (Header)Serializer.Deserialize(new MemoryStream(data), HeaderType);

            /*FieldInfo[] fields = header.GetType().GetFields();
            for (int i = 0; i < fields.Length; i++)
            {
                //if (fields[i].GetCustomAttributes(typeof(HeaderInfoAttribute), false).Length > 0)
                {
                    object val = pr.ReadObject();
                    fields[i].SetValue(header, val);
                }
            }
            return header;*/
        }
    }
}