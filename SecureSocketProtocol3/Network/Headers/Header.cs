using ProtoBuf;
using SecureSocketProtocol3.Hashers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

/*
    Secure Socket Protocol
    Copyright (C) 2016 AnguisCaptor

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

namespace SecureSocketProtocol3.Network.Headers
{
    [SerializableAttribute]
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
            if (pr.Position + 2 > pr.Buffer.Length)
                return null;

            ushort size = pr.ReadUShort();

            if (pr.Position + size > pr.Buffer.Length)
                return null;

            //byte[] data = pr.ReadBytes(size);
            Header header = (Header)Serializer.Deserialize(new MemoryStream(pr.Buffer, pr.Position, size), HeaderType);
            pr.Position += size;
            return header;

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