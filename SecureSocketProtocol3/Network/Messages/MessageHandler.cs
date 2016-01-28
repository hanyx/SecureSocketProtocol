using ProtoBuf;
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
                uint messageId = BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.Unicode.GetBytes(IdentifyKey)), 0);
                if (MessageType.BaseType == null)
                    throw new Exception("IMessage is not the base type");
                if (MessageType.GetConstructor(new Type[0]) == null)
                    throw new Exception("The type must contain a constructor with no arguments");
                if (Messages.ContainsKey(messageId))
                    return false;

                Messages.Add(messageId, MessageType);
                return true;
            }
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

        /// <summary>
        /// This method should only be called when handshake is successful
        /// </summary>
        internal void ResetMessages()
        {
            Messages.Clear();
        }

        internal IMessage DeSerialize(PayloadReader pr, uint MessageId, int MessageLength)
        {
            Type type = null;
            if (!Messages.TryGetValue(MessageId, out type))
                return null;

            ISerialization serializer = GetSerializer(type);
            if (serializer != null)
            {
                return serializer.Deserialize(pr.Buffer, pr.Position, MessageLength - pr.Position, type);
            }
            return null;
        }

        internal ISerialization GetSerializer(IMessage Message)
        {
            object[] attributes = Message.GetType().GetCustomAttributes(typeof(SerializationAttribute), false);

            if (attributes.Length > 0)
            {
                return (attributes[0] as SerializationAttribute).Serializer;
            }

            ISerialization serializer = Message.onGetSerializer();

            if (serializer == null)
                return connection.Client.IsServerSided ? connection.Client.Server.serverProperties.DefaultSerializer : connection.Client.Properties.DefaultSerializer;
            return serializer;
        }

        internal ISerialization GetSerializer(Type MessageType)
        {
            object[] attributes = MessageType.GetCustomAttributes(typeof(SerializationAttribute), false);

            if (attributes.Length > 0)
            {
                return (attributes[0] as SerializationAttribute).Serializer;
            }

            ISerialization serializer = (Activator.CreateInstance(MessageType) as IMessage).onGetSerializer();

            if (serializer == null)
                return connection.Client.IsServerSided ? connection.Client.Server.serverProperties.DefaultSerializer : connection.Client.Properties.DefaultSerializer;
            return serializer;
        }
    }
}