using ProtoBuf;
using SecureSocketProtocol3.Compressions;
using SecureSocketProtocol3.Hashers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages
{
    public class MessageHandler
    {
        private SortedList<uint, Type> Messages;
        internal uint Seed { get; private set; }
        private CRC32 hasher;

        public MessageHandler(uint Seed)
        {
            this.Messages = new SortedList<uint, Type>();
            this.hasher = new CRC32(CRC32.DefaultPolynomial + Seed);
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

            return (IMessage)Serializer.Deserialize(new MemoryStream(pr.Buffer, pr.Position, MessageLength - pr.Position), type);
        }
    }
}