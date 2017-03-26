﻿using ProtoBuf;
using SecureSocketProtocol3.Hashers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

/*
    The MIT License (MIT)

    Copyright (c) 2016 AnguisCaptor

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
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

        public static void Serialize(Header header, MemoryStream TargetStream)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                PayloadWriter pw = new PayloadWriter(TargetStream);
                Serializer.Serialize(ms, header);
                pw.WriteUShort((ushort)ms.Length);
                pw.WriteBytes(ms.GetBuffer(), 0, (int)ms.Length);
            }
        }

        public static byte[] Serialize(Header header)
        {
            using(MemoryStream ms = new MemoryStream())
            using(PayloadWriter pw = new PayloadWriter())
            {
                Serializer.Serialize(ms, header);
                pw.WriteUShort((ushort)ms.Length);
                pw.WriteBytes(ms.GetBuffer(), 0, (int)ms.Length);
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
            using (MemoryStream ms = new MemoryStream(pr.Buffer, pr.Position, size))
            {
                Header header = (Header)Serializer.Deserialize(ms, HeaderType);
                pr.Position += size;
                return header;
            }
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