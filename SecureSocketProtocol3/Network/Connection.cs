using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Diagnostics;
using SecureSocketProtocol3.Utils;
using System.IO;
using SecureSocketProtocol3.Security.Encryptions;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Network.Messages.TCP;
using SecureSocketProtocol3.Misc;
using System.Threading;
using SecureSocketProtocol3.Network.MazingHandshake;
using ProtoBuf;
using SecureSocketProtocol3.Compressions;
using SecureSocketProtocol3.Security.Obfuscation;
using SecureSocketProtocol3.Security.Layers;
using SecureSocketProtocol3.Security.Handshakes;
using SecureSocketProtocol3.Security.Serialization;

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

namespace SecureSocketProtocol3.Network
{
    public class Connection : TinySocket
    {
        public bool Connected { get; private set; }
        public SSPClient Client { get; private set; }
        private Socket Handle { get { return Client.Handle; } }
        private Stopwatch LastPacketRecvSW = new Stopwatch();
        private Stopwatch LastPacketSendSW = new Stopwatch();
        internal MessageHandler messageHandler { get; private set; }
        internal SortedList<ulong, Type> RegisteredOperationalSockets { get; private set; }
        internal SortedList<ushort, OperationalSocket> OperationalSockets { get; private set; }
        internal SortedList<int, SyncObject> Requests { get; private set; }

        internal SyncObject InitSync { get; private set; }

        internal HeaderList Headers { get; private set; }

        //locks
        internal object NextRandomIdLock = new object();
        private object SendLock = new object();


        //Security
        public int PrivateSeed { get; private set; }
        internal AesCtrLayer HeaderEncryption { get; private set; }

        //connection info
        public ulong PacketsIn { get; private set; }
        public ulong DataIn { get; private set; }
        public ulong PacketsOut { get; private set; }
        public ulong DataOut { get; private set; }
        public ulong DataCompressedIn { get; private set; }

        internal List<Thread> ConnectionThreads { get; private set; }

        /// <summary>
        /// Get the time when the last packet was received
        /// </summary>
        public TimeSpan LastPacketReceivedElapsed { get { return LastPacketRecvSW.Elapsed; } }

        /// <summary>
        /// Get the time when the last packet was send
        /// </summary>
        public TimeSpan LastPacketSendElapsed { get { return LastPacketSendSW.Elapsed; } }

        private bool _handShakeCompleted;
        private bool HandShakeCompleted
        {
            get
            {
                if (_handShakeCompleted)
                    return true;

                _handShakeCompleted = Client.handshakeSystem.CompletedAllHandshakes;
                return _handShakeCompleted;
            }
        }

        public byte[] NetworkKey { get { return Client.PreComputes.NetworkKey; } }
        public byte[] NetworkKeySalt { get { return Client.PreComputes.NetworkKeySalt; } }
        
        public Connection(SSPClient client)
            : base(client.Handle)
        {
            this.Client = client;
            this.Connected = true;
            this.Headers = new HeaderList(this);
            this.InitSync = new SyncObject(this);
            this.RegisteredOperationalSockets = new SortedList<ulong, Type>();
            this.Requests = new SortedList<int, SyncObject>();
            this.OperationalSockets = new SortedList<ushort, OperationalSocket>();
            this.ConnectionThreads = new List<Thread>();

            this.PrivateSeed = Client.PreComputes.PrivateSeed;

            this.HeaderEncryption = new AesCtrLayer(this);

            this.messageHandler = new MessageHandler((uint)PrivateSeed + 0x0FA453FB, this);
            this.messageHandler.AddMessage(typeof(MsgHandshake), "MAZE_HAND_SHAKE");
            this.messageHandler.AddMessage(typeof(MsgHandshakeFinish), "HANDSHAKE_FINISH");

            this.messageHandler.AddMessage(typeof(MsgCreateConnection), "CREATE_CONNECTION");
            this.messageHandler.AddMessage(typeof(MsgCreateConnectionResponse), "CREATE_CONNECTION_RESPONSE");

            this.messageHandler.AddMessage(typeof(MsgOpDisconnect), "OP_DISCONNECT");
            this.messageHandler.AddMessage(typeof(MsgOpDisconnectResponse), "OP_DISCONNECT_RESPONSE");

            this.messageHandler.AddMessage(typeof(MsgKeepAlive), "KEEP_ALIVE");

            Headers.RegisterHeader(typeof(SystemHeader));
            Headers.RegisterHeader(typeof(ConnectionHeader));
            Headers.RegisterHeader(typeof(RequestHeader));
            Headers.RegisterHeader(typeof(NullHeader));

            base._connection = this;
        }

        /// <summary>
        /// Send data to the established connection
        /// </summary>
        /// <param name="Message">The data to send</param>
        /// <param name="Header">The Header to use for adding additional information</param>
        /// <param name="OpSocket">The OperationalSocket that has been used for this Message</param>
        internal int SendMessage(IMessage Message, Header Header, OperationalSocket OpSocket = null)
        {
            lock (SendLock)
            {
                if (!Connected)
                    return -1;

                if (Message == null)
                    throw new ArgumentException("Message cannot be null");
                if (Header == null)
                    throw new ArgumentException("Header cannot be null");

                ISerialization serializer = messageHandler.GetSerializer(Message);

                if (serializer == null)
                {
                    throw new Exception("No serializer is specified for message type " + Message.GetType().FullName);
                }

                SocketHeader socketHeader = new SocketHeader();
                socketHeader.ConnectionId = OpSocket != null ? OpSocket.ConnectionId : (ushort)0;
                socketHeader.CurPacketId = (byte)PacketsOut;
                socketHeader.HeaderId = OpSocket != null ? OpSocket.Headers.GetHeaderId(Header) : Headers.GetHeaderId(Header);
                socketHeader.MessageId = OpSocket != null ? OpSocket.MessageHandler.GetMessageId(Message.GetType()) : messageHandler.GetMessageId(Message.GetType());
                socketHeader.SerializedHeader = Header.Serialize(Header);


                //prepare payload
                byte[] EncryptedPayload = new byte[0];
                int outOffset = 0;
                int outLength = 0;
                using (MemoryStream stream = new MemoryStream())
                {
                    //serialize header+payload
                    Header.Serialize(socketHeader, stream);
                    serializer.Serialize(Message, stream);
                        
                    //Encrypt Payload
                    Client.layerSystem.ApplyLayers(stream.GetBuffer(), 0, (int)stream.Length, ref EncryptedPayload, ref outOffset, ref outLength);
                }

                //prepare HMAC if any used
                byte[] HMAC = new byte[0];

                if (Client.DataIntegrityLayer != null)
                {
                    HMAC = Client.DataIntegrityLayer.ComputeHash(Client, EncryptedPayload, 0, EncryptedPayload.Length);

                    if (HMAC == null || (HMAC != null && HMAC.Length != Client.DataIntegrityLayer.FixedLength))
                        throw new Exception("DataIntegrityLayer FixedLength does not match GetHash");
                }

                //prepare start - Payload Length header
                byte[] EncryptedHeader = null;
                using (PayloadWriter outStream = new PayloadWriter())
                {
                    outStream.WriteThreeByteInteger(EncryptedPayload.Length);
                    outStream.WriteBytes(HMAC);
                    EncryptedHeader = outStream.ToByteArray();

                    outOffset = 0;
                    outLength = 0;
                    HeaderEncryption.ApplyLayer(EncryptedHeader, 0, EncryptedHeader.Length, ref EncryptedHeader, ref outOffset, ref outLength);
                }

                byte[] FinalOutMessage = new byte[EncryptedHeader.Length + EncryptedPayload.Length];
                Array.Copy(EncryptedHeader, 0, FinalOutMessage, 0, EncryptedHeader.Length);
                Array.Copy(EncryptedPayload, 0, FinalOutMessage, EncryptedHeader.Length, EncryptedPayload.Length);
                
                try
                {
                    for (int i = 0; i < FinalOutMessage.Length;)
                    {
                        int len = i + 65535 < FinalOutMessage.Length ? 65535 : FinalOutMessage.Length - i;
                        Handle.Send(FinalOutMessage, i, len, SocketFlags.None);
                        i += len;
                    }
                }
                catch (Exception ex)
                {
                    Disconnect();
                    return -1;
                }

                SysLogger.Log("Send " + FinalOutMessage.Length, SysLogType.Network);
                PacketsOut++;

                return FinalOutMessage.Length;
            }
        }

        private void ProcessMessage(SystemPacket systemPacket)
        {
            ConnectionHeader ConHeader = systemPacket.Header as ConnectionHeader;
            if (ConHeader != null)
            {
                lock (OperationalSockets)
                {
                    if (systemPacket.OpSocket != null)
                    {
                        systemPacket.OpSocket.PacketQueue.Enqueue(systemPacket);
                    }
                    else
                    {
                        //Disconnect ?
                    }
                }
            }
            else
            {
                systemPacket.Message.ProcessPayload(Client, null);
            }
        }

        public void ApplyNewKey(byte[] key, byte[] salt)
        {
            byte[] MixedKey = Client.PreComputes.NetworkKey;
            byte[] MixedSalt = Client.PreComputes.NetworkKeySalt;

            for (int i = 0; i < MixedKey.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    MixedKey[i] += key[j];
                }
            }
            for (int i = 0; i < MixedSalt.Length; i++)
            {
                for (int j = 0; j < salt.Length; j++)
                {
                    MixedSalt[i] += salt[j];
                }
            }

            this.HeaderEncryption.ApplyKey(MixedKey, MixedSalt);

            Client.DataIntegrityLayer.ApplyKey(MixedKey, MixedSalt);
            Client.layerSystem.ApplyKeyToLayers(MixedKey, MixedSalt);
        }

        internal Thread CreateNewThread(ThreadStart threadStart)
        {
            Thread thread = new Thread(threadStart);
            
            lock (ConnectionThreads)
            {
                ConnectionThreads.Add(thread);
            }
            return thread;
        }

        internal SyncObject RegisterRequest(ref int RequestId)
        {
            lock (Requests)
            {
                SyncObject syncObj = new SyncObject(this);
                SecureRandom rnd = new SecureRandom();

                do
                {
                    RequestId = rnd.Next();
                }
                while (Requests.ContainsKey(RequestId));

                Requests.Add(RequestId, syncObj);

                return syncObj;
            }
        }

        public void Disconnect()
        {
            if (Client.TimingConfiguration.Enable_Timing)
            {
                if (!HandShakeCompleted)
                {
                    //When a disconnection occurs, could be of decryption failure or authentication failure
                    Thread.Sleep(Client.TimingConfiguration.Authentication_WrongPassword);
                }
            }

            Connected = false;
            Client.Disconnect();
        }

        protected override void onReceiveHeader(byte[] Data, int Offset)
        {
            this.LastPacketRecvSW = Stopwatch.StartNew();

            if (Client.Server != null && Client.Server.serverProperties != null)
            {
                if (Client.ConnectionTime > Client.Server.serverProperties.ClientTimeConnected)
                {
                    Disconnect();
                    return;
                }
            }

            lock (HeaderEncryption)
            {
                byte[] decryptedHeader = new byte[0];
                int decOffset = 0;
                int decLen = 0;
                HeaderEncryption.RemoveLayer(Data, Offset, HEADER_SIZE, ref decryptedHeader, ref decOffset, ref decLen);

                Array.Copy(decryptedHeader, 0, Data, Offset, decLen);
            }
        }

        protected override void onReceivePayload(byte[] Data, int Offset, int Length)
        {
            this.LastPacketRecvSW = Stopwatch.StartNew();
            PacketsIn++;

            if (Client.DataIntegrityLayer != null)
            {
                if (!Client.DataIntegrityLayer.Verify(Client, base.PayloadHMAC, Data, Offset, Length))
                {
                    //Hash missmatch
                    Disconnect();
                    return;
                }
            }


            byte[] DecryptedBuffer = null;
            int DecryptedOffset = 0;
            int DecryptedBuffLen = 0;
            Client.layerSystem.RemoveLayers(Data, Offset, Length, ref DecryptedBuffer, ref DecryptedOffset, ref DecryptedBuffLen);

            if (DecryptedBuffer == null)
            {
                //failed to decrypt data
                onDisconnect();
                return;
            }

            using (PayloadReader pr = new PayloadReader(DecryptedBuffer) { Position = DecryptedOffset })
            {
                int oldOffset = pr.Position;
                SocketHeader socketHeader = Header.DeSerialize(typeof(SocketHeader), pr) as SocketHeader;
                
                OperationalSocket OpSocket = null;
                if (socketHeader.ConnectionId > 0)
                {
                    lock (OperationalSockets)
                    {
                        if (!OperationalSockets.TryGetValue(socketHeader.ConnectionId, out OpSocket))
                        {
                            //strange...
                            //Disconnect();
                            return;
                        }
                    }
                }

                Type type = Headers.GetHeaderType(socketHeader.HeaderId);

                if (type != null)
                {
                    Header header = null;

                    using (PayloadReader headerPr = new PayloadReader(socketHeader.SerializedHeader))
                    {
                        header = Header.DeSerialize(type, headerPr);
                    }

                    if (header == null)
                    {
                        Disconnect();
                        return;
                    }
                    
                    int readLen = pr.Position - oldOffset;
                    IMessage message = OpSocket != null ? OpSocket.MessageHandler.DeSerialize(pr, socketHeader.MessageId, DecryptedBuffLen - readLen) : messageHandler.DeSerialize(pr, socketHeader.MessageId, DecryptedBuffLen - readLen);
                    
                    if (message != null)
                    {
                        message.RawSize = Length;
                        message.Header = header;
                        message.DecompressedRawSize = DecryptedBuffLen;

                        if (!HandShakeCompleted)
                        {
                            if (message.GetType() != typeof(MsgKeepAlive) && message.GetType() != typeof(MsgHandshakeFinish))
                            {
                                Handshake CurHandshake = Client.handshakeSystem.GetCurrentHandshake();

                                if (CurHandshake != null)
                                {
                                    while (Connected && !CurHandshake.FinishedInitialization)
                                        Thread.Sleep(100); //will improve this later

                                    //process the handshake messages straight away
                                    CurHandshake.onReceiveMessage(message);
                                }
                                else
                                {
                                    //??
                                    Disconnect();
                                }
                            }
                            else if (message.GetType() == typeof(MsgHandshakeFinish))
                            {
                                message.ProcessPayload(Client, null);
                            }
                        }
                        else
                        {
                            ProcessMessage(new SystemPacket(header, message, socketHeader.ConnectionId, OpSocket));
                        }
                    }
                }
                else
                {
                    onDisconnect();
                    return;
                }
            }
        }

        protected override void onDisconnect()
        {
            Disconnect();
        }

        protected override void onSendMessage(byte[] Data, int Offset, int Length)
        {

        }
    }
}