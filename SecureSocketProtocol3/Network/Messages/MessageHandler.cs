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

        /*public IMessage HandleMessage(PayloadReader reader, uint MessageId)
        {
            lock (Messages)
            {
                Type type = null;
                if (!Messages.TryGetValue(MessageId, out type))
                    return null;

                IMessage message = null;//IMessage.DeSerialize(type, reader);
                return message;
            }
        }*/

        public IMessage HandleUdpMessage(PayloadReader reader, uint MessageId)
        {
            lock (Messages)
            {
                Type type = null;
                if (!Messages.TryGetValue(MessageId, out type))
                    return null;

                IMessage message = null;//IMessage.DeSerialize(type, reader);
                message.RawSize = reader.Length;
                return message;
            }
        }

        /// <summary>
        /// This method should only be called when handshake is successful
        /// </summary>
        internal void ResetMessages()
        {
            Messages.Clear();
        }

        /// <summary>
        /// Serialize the Message to output stream
        /// </summary>
        /// <param name="message"></param>
        /// <param name="TargetStream"></param>
        /// <returns>The size of the serialzed message</returns>
        internal int EncryptMessage(Connection conn, IMessage message, MemoryStream TargetStream)
        {
            PayloadWriter pw = new PayloadWriter(TargetStream);
            int PayloadPos = pw.Position;

            Serializer.Serialize(TargetStream, message);

            #region Security
            //compress data
            /*if (CompressionAlgorithm.QuickLZ == (conn.CompressionAlgorithm & CompressionAlgorithm.QuickLZ))
            {
                UnsafeQuickLZ quickLz = new UnsafeQuickLZ();
                byte[] compressed = quickLz.compress(TargetStream.GetBuffer(), (uint)Connection.HEADER_SIZE, (uint)TargetStream.Length - Connection.HEADER_SIZE);

                if (compressed != null &&
                    compressed.Length + Connection.HEADER_SIZE < TargetStream.Length) //only apply compression if it's smaller then the original data
                {
                    TargetStream.Position = Connection.HEADER_SIZE;
                    TargetStream.Write(compressed, 0, compressed.Length);

                    if (TargetStream.Length != compressed.Length + Connection.HEADER_SIZE)
                        TargetStream.SetLength(compressed.Length + Connection.HEADER_SIZE);
                }
            }*/

            //encrypt all the data
            if (EncAlgorithm.HwAES == (conn.EncryptionAlgorithm & EncAlgorithm.HwAES))
            {
                lock (conn.EncAES)
                {
                    //no need to re-size the stream here, AES will encrypt at the same size or bigger then the stream, so data will be overwritten
                    byte[] encrypted = conn.EncAES.Encrypt(TargetStream.GetBuffer(), Connection.HEADER_SIZE, (int)TargetStream.Length - Connection.HEADER_SIZE);
                    TargetStream.Position = Connection.HEADER_SIZE;
                    TargetStream.Write(encrypted, 0, encrypted.Length);
                }
            }
            if (EncAlgorithm.WopEx == (conn.EncryptionAlgorithm & EncAlgorithm.WopEx))
            {
                lock (conn.PayloadEncryption)
                {
                    conn.PayloadEncryption.Encrypt(TargetStream.GetBuffer(), Connection.HEADER_SIZE, (int)TargetStream.Length - Connection.HEADER_SIZE);
                }
            }
            #endregion

            return pw.Length - PayloadPos;
        }

        internal void DecryptMessage(Connection conn, byte[] InData, int InOffset, int inLen, ref byte[] OutData, ref int OutLen)
        {
            #region Encryption
            if (EncAlgorithm.HwAES == (conn.EncryptionAlgorithm & EncAlgorithm.HwAES))
            {
                lock (conn.EncAES)
                {
                    if (OutData != null)
                    {
                        OutData = conn.EncAES.Decrypt(OutData, 0, OutLen);
                    }
                    else
                    {
                        OutData = conn.EncAES.Decrypt(InData, InOffset, inLen);
                    }
                    OutLen = OutData.Length;
                }
            }
            /*if (EncAlgorithm.WopEx == (EncryptionAlgorithm & EncAlgorithm.WopEx))
            {
                lock (PayloadEncryption)
                {
                    if (DecryptedBuffer != null)
                    {
                        PayloadEncryption.Decrypt(DecryptedBuffer, DecryptedBuffOffset, DecryptedBuffLen);
                    }
                    else
                    {
                        PayloadEncryption.Decrypt(Buffer, ReadOffset, PayloadLen);
                    }
                    DecryptedBuffer = Buffer;
                    DecryptedBuffOffset = ReadOffset;
                    DecryptedBuffLen = PayloadLen;
                }
            }*/
            #endregion

            #region Compression
            /*if (CompressionAlgorithm.QuickLZ == (this.CompressionAlgorithm & SecureSocketProtocol3.CompressionAlgorithm.QuickLZ))
            {
                if (DecryptedBuffer != null)
                {
                    byte[] temp = QuickLZ.decompress(DecryptedBuffer, (uint)DecryptedBuffOffset);
                    if (temp != null)
                    {
                        DecryptedBuffer = temp;
                        DecryptedBuffOffset = 0;
                        DecryptedBuffLen = temp.Length;
                        DataCompressedIn += (ulong)DecryptedBuffLen;
                    }
                }
                else
                {
                    byte[] temp = DecryptedBuffer = QuickLZ.decompress(Buffer, (uint)ReadOffset);
                    if (temp != null)
                    {
                        DecryptedBuffer = temp;
                        DecryptedBuffOffset = 0;
                        DecryptedBuffLen = temp.Length;
                        DataCompressedIn += (ulong)DecryptedBuffLen;
                    }
                }
                DecryptedBuffLen = DecryptedBuffer.Length;
            }*/
            #endregion
        }

        internal IMessage DeSerialize(PayloadReader pr, uint MessageId)
        {
            Type type = null;
            if (!Messages.TryGetValue(MessageId, out type))
                return null;

            int len = pr.Length - pr.Position;
            IMessage message = (IMessage)Serializer.Deserialize(new MemoryStream(pr.Buffer, pr.Position, len), type);
            pr.Position += len;
            return message;
        }
    }
}