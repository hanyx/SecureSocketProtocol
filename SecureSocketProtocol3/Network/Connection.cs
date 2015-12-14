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
        
        internal SyncObject HandshakeSync { get; private set; }
        internal SyncObject InitSync { get; private set; }

        internal HeaderList Headers { get; private set; }
        
        //locks
        internal object NextRandomIdLock = new object();
        private object SendLock = new object();


        //Security
        internal WopEx HeaderEncryption { get; private set; }
        public int PrivateSeed { get; private set; }
        private DataConfuser headerConfuser { get; set; }

        //connection info
        public ulong PacketsIn { get; private set; }
        public ulong DataIn { get; private set; }
        public ulong PacketsOut { get; private set; }
        public ulong DataOut { get; private set; }
        public ulong DataCompressedIn { get; private set; }

        /// <summary>
        /// Get the time when the last packet was received
        /// </summary>
        public TimeSpan LastPacketReceivedElapsed { get { return LastPacketRecvSW.Elapsed; } }

        /// <summary>
        /// Get the time when the last packet was send
        /// </summary>
        public TimeSpan LastPacketSendElapsed { get { return LastPacketSendSW.Elapsed; } }

        internal bool HandShakeCompleted { get; set; }

        internal byte[] NetworkKey
        {
            get
            {
                return Client.Server != null ? Client.Server.serverProperties.NetworkKey : Client.Properties.NetworkKey;
            }
        }

        public Connection(SSPClient client)
            : base(client.Handle)
        {
            this.Client = client;

            this.Connected = true;
            this.Headers = new HeaderList(this);
            this.HandshakeSync = new SyncObject(this);
            this.InitSync = new SyncObject(this);
            this.RegisteredOperationalSockets = new SortedList<ulong, Type>();
            this.Requests = new SortedList<int, SyncObject>();
            this.OperationalSockets = new SortedList<ushort, OperationalSocket>();
            
            //generate the header encryption
            PrivateSeed = NetworkKey.Length >= 4 ? BitConverter.ToInt32(NetworkKey, 0) : 0xBEEF;

            for (int i = 0; i < NetworkKey.Length; i++)
                PrivateSeed += NetworkKey[i];

            byte[] SaltKey = new byte[NetworkKey.Length];
            Array.Copy(NetworkKey, SaltKey, SaltKey.Length);

            for (int i = 0; i < SaltKey.Length; i++)
                SaltKey[i] += (byte)PrivateSeed;

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(PrivateSeed, 5, ref encCode, ref decCode);
            this.HeaderEncryption = new WopEx(NetworkKey, SaltKey, PrivateSeed, encCode, decCode, WopEncMode.GenerateNewAlgorithm, 5, false);

            this.headerConfuser = new DataConfuser(PrivateSeed, Connection.HEADER_SIZE);

            this.messageHandler = new MessageHandler((uint)PrivateSeed + 0x0FA453FB);
            this.messageHandler.AddMessage(typeof(MsgHandshake), "MAZE_HAND_SHAKE");
            this.messageHandler.AddMessage(typeof(MsgCreateConnection), "CREATE_CONNECTION");
            this.messageHandler.AddMessage(typeof(MsgCreateConnectionResponse), "CREATE_CONNECTION_RESPONSE");

            this.messageHandler.AddMessage(typeof(MsgInitOk), "INIT_OK");
            this.messageHandler.AddMessage(typeof(MsgGetNextId), "GET_NEXT_NUMBER");
            this.messageHandler.AddMessage(typeof(MsgGetNextIdResponse), "GET_NEXT_NUMBER_RESPONSE");

            this.messageHandler.AddMessage(typeof(MsgOpDisconnect), "OP_DISCONNECT");
            this.messageHandler.AddMessage(typeof(MsgOpDisconnectResponse), "OP_DISCONNECT_RESPONSE");

            this.messageHandler.AddMessage(typeof(MsgKeepAlive), "KEEP_ALIVE");

            Headers.RegisterHeader(typeof(SystemHeader));
            Headers.RegisterHeader(typeof(ConnectionHeader));
            Headers.RegisterHeader(typeof(RequestHeader));
        }

        /// <summary>
        /// Send data to the established connection
        /// </summary>
        /// <param name="Message">The data to send</param>
        /// <param name="Header">The Header to use for adding additional information</param>
        /// <param name="feature">The Feature that has been used for this Message</param>
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

                ushort HeaderId = OpSocket != null ? OpSocket.Headers.GetHeaderId(Header) : Headers.GetHeaderId(Header);
                byte[] SerializedHeader = Header.Serialize(Header);

                uint messageId = OpSocket != null ? OpSocket.MessageHandler.GetMessageId(Message.GetType()) : messageHandler.GetMessageId(Message.GetType());

                if (SerializedHeader.Length >= MAX_PACKET_SIZE)
                    throw new ArgumentException("Header length cannot be greater then " + MAX_PAYLOAD);

                using (MemoryStream outStream = new MemoryStream())
                using (PayloadWriter pw = new PayloadWriter(outStream))
                {
                    pw.WriteBytes(new byte[HEADER_SIZE], 0, HEADER_SIZE); //reserve space

                    using (MemoryStream TempStream = new MemoryStream())
                    using (PayloadWriter TempPw = new PayloadWriter(TempStream))
                    {
                        byte[] outEncrypted = null;
                        int outOffset = 0;
                        int outLength = 0;

                        TempPw.WriteBytes(SerializedHeader);
                        TempPw.WriteUInteger(messageId);
                        Serializer.Serialize(TempStream, Message);

                        Client.layerSystem.ApplyLayers(TempStream.GetBuffer(), 0, (int)TempStream.Length, ref outEncrypted, ref outOffset, ref outLength);
                        pw.WriteBytes(outEncrypted, outOffset, outLength);

                        byte[] DataHash = Client.DataIntegrityLayer.ComputeHash(Client, outEncrypted, outOffset, outLength);

                        if (DataHash == null || (DataHash != null && DataHash.Length != Client.DataIntegrityLayer.FixedLength))
                            throw new Exception("DataIntegrityLayer FixedLength does not match GetHash");

                        pw.WriteBytes(DataHash);
                    }

                    if (pw.Length > MAX_PACKET_SIZE)
                        throw new OverflowException("Message size cannot be greater then " + MAX_PACKET_SIZE);

                    int PayloadLength = (int)pw.Length - Connection.HEADER_SIZE;
                    byte CurPacketId = 0;
                    ushort ConnectionId = OpSocket != null ? OpSocket.ConnectionId : (ushort)0;

                    byte checksum = 0;
                    checksum += (byte)PayloadLength;
                    checksum += CurPacketId;
                    checksum += (byte)ConnectionId;
                    checksum += (byte)HeaderId;

                    pw.Position = 0;
                    pw.WriteThreeByteInteger(PayloadLength); //length
                    pw.WriteByte(CurPacketId); //cur packet id
                    pw.WriteUShort(ConnectionId); //Connection Id
                    pw.WriteUShort(HeaderId); //Header Id
                    pw.WriteByte(checksum);

                    //encrypt the header
                    lock (HeaderEncryption)
                    {
                        outStream.Position = 0;
                        HeaderEncryption.Encrypt(pw.GetBuffer(), 0, HEADER_SIZE, outStream);

                        /*byte[] temp = outStream.GetBuffer();
                        headerConfuser.Obfuscate(ref temp, 0);

                        outStream.Position = 0;
                        outStream.Write(temp, 0, temp.Length);*/
                    }

                    int SendNum = 0;

                    try
                    {
                        for (int i = 0; i < outStream.Length;)
                        {
                            int len = i + 65535 < outStream.Length ? 65535 : (int)outStream.Length - i;
                            Handle.Send(outStream.GetBuffer(), i, len, SocketFlags.None);
                            i += len;
                            SendNum += len;
                        }
                    }
                    catch (Exception ex)
                    {
                        Disconnect();
                        return -1;
                    }

                    SysLogger.Log("Send " + outStream.Length, SysLogType.Network);

                    PacketsOut++;
                    DataOut += (ulong)outStream.Length;
                    this.LastPacketSendSW = Stopwatch.StartNew();
                    return SendNum;
                }
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
                        Header header = ConHeader.DeserializeHeader(systemPacket.OpSocket);
                        if (header == null)
                        {
                            return;
                        }

                        systemPacket.OpSocket.onReceiveMessage(systemPacket.Message, header);
                    }
                    else
                    {

                    }
                }
            }
            else
            {
                systemPacket.Message.ProcessPayload(Client, null);
            }
        }

        internal void ApplyNewKey(Mazing mazeHandshake, byte[] key, byte[] salt)
        {
            Console.WriteLine("Is Server ? " + Client.IsServerSided + ", " + BitConverter.ToString(key).Substring(0, 100));

            mazeHandshake.ApplyKey(this.HeaderEncryption, key);
            mazeHandshake.ApplyKey(this.HeaderEncryption, salt);

            Client.DataIntegrityLayer.ApplyKey(key, salt);

            Client.layerSystem.ApplyKeyToLayers(Client, key, salt);
        }

        internal SyncObject RegisterRequest(ref int RequestId)
        {
            lock (Requests)
            {
                SyncObject syncObj = new SyncObject(this);
                FastRandom rnd = new FastRandom();

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

            //let's check the certificate
            if (Client.Server != null && Client.Server.serverProperties != null)
            {
                if (Client.ConnectionTime > Client.Server.serverProperties.ClientTimeConnected)
                {
                    //we need to wait till the time is right
                    Disconnect();
                    return;
                }
            }

            lock (HeaderEncryption)
            {
                //headerConfuser.Deobfuscate(ref Data, Offset);
                HeaderEncryption.Decrypt(Data, Offset, HEADER_SIZE, new MemoryStream(Data) { Position = Offset });
            }
        }

        protected override void onReceivePayload(byte[] Data, int Offset, int Length)
        {
            this.LastPacketRecvSW = Stopwatch.StartNew();
            PacketsIn++;

            int PayloadLength = Length - Client.DataIntegrityLayer.FixedLength;

            //let's check the Data Integrity Layer
            byte[] IntegrityData = new byte[Client.DataIntegrityLayer.FixedLength];
            Buffer.BlockCopy(Data, (Offset + PayloadLen) - IntegrityData.Length, IntegrityData, 0, IntegrityData.Length);
            if (!Client.DataIntegrityLayer.Verify(Client, IntegrityData, Data, Offset, PayloadLength))
            {
                //Hash missmatch
                Disconnect();
                return;
            }

            byte[] DecryptedBuffer = null;
            int DecryptedOffset = 0;
            int DecryptedBuffLen = 0;

            Client.layerSystem.RemoveLayers(Data, Offset, PayloadLength, ref DecryptedBuffer, ref DecryptedOffset, ref DecryptedBuffLen);

            if (DecryptedBuffer == null)
            {
                //failed to decrypt data
                onDisconnect();
                return;
            }

            using (PayloadReader pr = new PayloadReader(DecryptedBuffer) { Position = DecryptedOffset })
            {
                OperationalSocket OpSocket = null;
                if (ConnectionId > 0)
                {
                    lock (OperationalSockets)
                    {
                        if (!OperationalSockets.TryGetValue(ConnectionId, out OpSocket))
                        {
                            //strange...
                            Disconnect();
                            return;
                        }
                    }
                }

                Type type = Headers.GetHeaderType(HeaderId);

                if (type != null)
                {
                    Header header = Header.DeSerialize(type, pr);

                    if (header == null)
                    {
                        Disconnect();
                        return;
                    }

                    uint MessageId = pr.ReadUInteger();
                    IMessage message = OpSocket != null ? OpSocket.MessageHandler.DeSerialize(pr, MessageId, DecryptedBuffLen) : messageHandler.DeSerialize(pr, MessageId, DecryptedBuffLen);

                    if (message != null)
                    {
                        message.RawSize = Length;
                        message.Header = header;

                        if (!HandShakeCompleted)
                        {
                            if (message.GetType() == typeof(MsgHandshake))
                            {
                                //process the handshake messages straight away
                                message.ProcessPayload(Client, null);
                            }
                        }
                        else
                        {
                            ProcessMessage(new SystemPacket(header, message, ConnectionId, OpSocket));
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