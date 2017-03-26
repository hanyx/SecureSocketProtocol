﻿using ProtoBuf;
using SecureSocketProtocol3.Network.Messages;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

namespace SecureSocketProtocol3.Security.Serialization
{
    public class ProtobufSerialization : ISerialization
    {
        public byte[] Serialize(Network.Messages.IMessage Message)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                Serialize(Message, stream);
                return stream.ToArray();
            }
        }

        public void Serialize(IMessage Message, MemoryStream stream)
        {
            Serializer.Serialize(stream, Message);
        }

        public Network.Messages.IMessage Deserialize(byte[] MessageData, int Offset, int Length, Type MessageType)
        {
            using (MemoryStream ms = new MemoryStream(MessageData, Offset, Length))
            {
                //ms.Position = Offset;
                return (IMessage)Serializer.Deserialize(MessageType, ms);
            }
        }
    }
}
