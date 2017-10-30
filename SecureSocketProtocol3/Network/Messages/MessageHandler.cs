﻿using ProtoBuf;
using SecureSocketProtocol3.Attributes;
using SecureSocketProtocol3.Compressions;
using SecureSocketProtocol3.Hashers;
using SecureSocketProtocol3.Security.Serialization;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
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

namespace SecureSocketProtocol3.Network.Messages
{
    public class MessageHandler
    {
        private SortedList<uint, Type> Messages;
        internal uint Seed { get; private set; }
        private CRC32 hasher;
        private Connection connection;

        public MessageHandler(uint Seed, Connection connection)
        {
            this.Messages = new SortedList<uint, Type>();
            this.hasher = new CRC32(CRC32.DefaultPolynomial + Seed);
            this.connection = connection;
        }

        /// <summary>
        /// Add a message
        /// </summary>
        /// <param name="message">The message type to add</param>
        /// <param name="IdentifyKey">The key to identify the sending and receiving message, the identify key must be unique</param>
        /// <returns>If false the message did already exist otherwise true</returns>
        public bool AddMessage(Type MessageType, string IdentifyKey)
        {
            lock (Messages)
            {
                if (MessageType.BaseType == null)
                    throw new Exception("IMessage is not the base type");
                if (MessageType.GetConstructor(new Type[0]) == null)
                    throw new Exception("The type must contain a constructor with no arguments");
                if (Messages.ContainsKey(GetMessageId(IdentifyKey)))
                    return false;

                Messages.Add(GetMessageId(IdentifyKey), MessageType);
                return true;
            }
        }

        public void RemoveMessage(string IdentifyKey)
        {
            lock (Messages)
            {
                if (Messages.ContainsKey(GetMessageId(IdentifyKey)))
                    Messages.Remove(GetMessageId(IdentifyKey));
            }
        }

        public uint GetMessageId(string IdentifyKey)
        {
            hasher.Initialize();
            return BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.Unicode.GetBytes(IdentifyKey)), 0);
        }

        /// <summary>
        /// Get the message id that was registered as a UINT
        /// </summary>
        /// <param name="MessageType">The message type</param>
        /// <returns>The message Id</returns>
        public uint GetMessageId(Type MessageType)
        {
            lock (Messages)
            {
                for (int i = 0; i < Messages.Count; i++)
                {
                    Type type = Messages.Values[i];
                    if (Messages.Values[i] == MessageType)
                        return Messages.Keys[i];
                }
                throw new Exception("Message Id not found, Message not registered ? " + MessageType.FullName);
            }
        }

        public Type GetMessageTypeById(uint MessageId)
        {
            Type type = null;
            Messages.TryGetValue(MessageId, out type);
            return type;
        }

        /// <summary>
        /// This method should only be called when handshake is successful
        /// </summary>
        internal void ResetMessages()
        {
            Messages.Clear();
        }

        public IMessage DeSerialize(PayloadReader pr, uint MessageId, int MessageLength)
        {
            Type type = null;
            if (!Messages.TryGetValue(MessageId, out type))
                return null;

            ISerialization serializer = GetSerializer(type);
            if (serializer != null)
            {
                return serializer.Deserialize(pr.Buffer, pr.Position, MessageLength, type);
            }
            return null;
        }

        public ISerialization GetSerializer(IMessage Message)
        {
            object[] attributes = Message.GetType().GetCustomAttributes(typeof(SerializationAttribute), false);

            if (attributes.Length > 0)
            {
                return (attributes[0] as SerializationAttribute).Serializer;
            }

            ISerialization serializer = Message.onGetSerializer();

            if (serializer == null)
                return connection.Client.IsServerSided ? connection.Client.Server.serverProperties.DefaultSerializer : connection.Client.ConnectedProperty.DefaultSerializer;
            return serializer;
        }

        public ISerialization GetSerializer(Type MessageType)
        {
            object[] attributes = MessageType.GetCustomAttributes(typeof(SerializationAttribute), false);

            if (attributes.Length > 0)
            {
                return (attributes[0] as SerializationAttribute).Serializer;
            }

            ISerialization serializer = (Activator.CreateInstance(MessageType) as IMessage).onGetSerializer();

            if (serializer == null)
                return connection.Client.IsServerSided ? connection.Client.Server.serverProperties.DefaultSerializer : connection.Client.ConnectedProperty.DefaultSerializer;
            return serializer;
        }
    }
}