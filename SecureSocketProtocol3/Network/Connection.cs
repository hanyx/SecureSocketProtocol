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
using SecureSocketProtocol3.Features;
using SecureSocketProtocol3.Compressions;
using SecureSocketProtocol3.Security.Obfuscators;

namespace SecureSocketProtocol3.Network
{
    public class Connection
    {
        internal static readonly byte[] VALIDATION = new byte[]
        {
            151, 221, 126, 222, 126, 142, 126, 208, 107, 209, 212, 218, 228, 167, 158, 252, 105, 147, 185, 178
        };

        private static readonly byte[] InitialVector = new byte[]
        {
            83, 210, 20, 80, 15, 131, 109, 63, 2, 143, 206, 152, 135, 66, 176, 37, 180, 108, 2, 49, 14, 237, 135, 160, 203,
            91, 31, 34, 200, 209, 62, 118, 97, 216, 21, 194, 26, 240, 123, 203, 255, 133, 163, 27, 11, 30, 15, 105, 237, 63,
            115, 92, 163, 27, 105, 158, 29, 236, 70, 58, 243, 206, 197, 230, 158, 133, 116, 70, 121, 50, 54, 59, 236, 31, 175,
            125, 60, 148, 175, 200, 6, 231, 19, 89, 126, 255, 165, 224, 193, 203, 55, 213, 112, 247, 101, 52, 9, 91, 146, 152,
            251, 69, 168, 123, 116, 99, 52, 10, 3, 198, 56, 251, 217, 148, 7, 171, 137, 24, 113, 111, 87, 70, 98, 134, 119,
            197, 214, 38, 39, 51, 129, 67, 233, 205, 190, 97, 251, 254, 80, 91, 56, 187, 63, 146, 125, 76, 140, 152, 7, 40,
            126, 252, 203, 91, 105, 108, 178, 216, 45, 233, 130, 69, 175, 121, 150, 206, 181, 127, 151, 136, 168, 170, 199, 214, 133,
            218, 181, 178, 177, 101, 92, 128, 108, 255, 230, 235, 197, 233, 245, 137, 186, 129, 165, 225, 162, 69, 61, 27, 106, 147,
            82, 122, 65, 42, 88, 50, 117, 104, 76, 20, 171, 71, 245, 55, 177, 30, 248, 66, 75, 31, 35, 68, 83, 150, 86,
            26, 107, 25, 237, 113, 190, 103, 1, 145, 182, 126, 220, 217, 216, 239, 231, 233, 146, 253, 60, 235, 72, 26, 200, 164,
            188, 80, 156, 184, 140, 106
        };

        /// <summary>
        /// The length contains always 2 bytes Unsigned Short
        /// 
        /// CurPacketId is only 1 byte and the number will increment everytime you send a packet
        /// If you send the CurPacketId but the number does not match at the server side
        /// The server will disconnect
        /// 
        /// The ConnectionId is being used for the OperationalSocket (Virtual Connection)
        /// 
        /// The HeaderId is just a number to know which header is being used for a packet
        /// 
        /// The Fragment Id is being used for if the packet is bigger then the MAX_PAYLOAD
        /// If the Fragment Id contains the flag 0x80 (128), this means that it is the last fragment
        /// If the FragmentId is bigger then 1 the Fragment is enabled
        /// The fragment id should never exceed 128
        /// 
        /// The checksum is all the information combined to a small hash of 1Byte
        /// 
        /// Fragment Full Size - Contains the full size for the packet
        /// 
        /// FeatureId - The Id of the Feature that has been used for additional features to add in the OperationalSocket
        /// </summary>

        public const int HEADER_SIZE = 16; //Headersize contains, length(USHORT) + CurPacketId(BYTE) + Connection Id(USHORT) + Header Id(USHORT) + Fragment (BYTE) + Checksum(BYTE) + FragmentFullSize(3Bytes) + FeatureId(INT)
        public const int MAX_PAYLOAD = ushort.MaxValue - HEADER_SIZE; //maximum size to receive at once, U_SHORT - HEADER_SIZE = 65529
        public const int MAX_FRAGMENT_SIZE = (1024 * 1024) * 5; //5MB packet is max

        public bool Connected { get; private set; }
        public decimal ClientId { get; internal set; }
        public SSPClient Client { get; private set; }
        private Socket Handle { get { return Client.Handle; } }
        private Stopwatch LastPacketSW = new Stopwatch();
        private byte[] Buffer = new byte[HEADER_SIZE + MAX_PAYLOAD];
        internal MessageHandler messageHandler { get; private set; }
        private TaskQueue<SystemPacket> SystemPackets;
        internal SortedList<ulong, Type> RegisteredOperationalSockets { get; private set; }
        internal SortedList<ushort, OperationalSocket> OperationalSockets { get; private set; }
        internal SortedList<int, SyncObject> Requests { get; private set; }

        private ReceiveType ReceiveState = ReceiveType.Header;
        internal SyncObject HandshakeSync { get; private set; }
        internal SyncObject InitSync { get; private set; }

        internal HeaderList Headers { get; private set; }
        
        //locks
        private object NextRandomIdLock = new object();
        private object SendLock = new object();

        //receive info
        private int ReadOffset = 0;
        private int WriteOffset = 0;
        private int ReadableDataLen = 0;
        private int TotalReceived = 0;

        //fragment information
        private byte[] FragmentBuffer = null;
        private int FragmentOffset = 0;
        private int FragmentFullSize = 0;

        //header info
        private int PayloadLen = 0;
        private byte CurPacketId = 0;
        private ushort ConnectionId = 0;
        private ushort HeaderId = 0;
        private byte FragmentId = 0;
        private byte HeaderChecksum = 0;
        private int FeatureId = 0;

        //Security
        internal WopEx HeaderEncryption { get; private set; }
        internal WopEx PayloadEncryption { get; private set; }
        internal HwAes EncAES { get; private set; }
        internal int PrivateSeed { get; private set; }
        internal UnsafeQuickLZ QuickLZ { get; private set; }
        private HeaderConfuser headerConfuser { get; set; }

        //connection info
        public ulong PacketsIn { get; private set; }
        public ulong DataIn { get; private set; }
        public ulong PacketsOut { get; private set; }
        public ulong DataOut { get; private set; }

        public ulong DataCompressedIn { get; private set; }

        internal bool HandShakeCompleted { get; set; }
        public EncAlgorithm EncryptionAlgorithm { get; internal set; }
        public CompressionAlgorithm CompressionAlgorithm { get; internal set; }

        public Connection(SSPClient client)
        {
            this.Client = client;
            this.Connected = true;
            this.Headers = new HeaderList(this);
            this.SystemPackets = new TaskQueue<SystemPacket>(onSystemPacket, 50);
            this.HandshakeSync = new SyncObject(this);
            this.InitSync = new SyncObject(this);
            this.RegisteredOperationalSockets = new SortedList<ulong, Type>();
            this.Requests = new SortedList<int, SyncObject>();
            this.OperationalSockets = new SortedList<ushort, OperationalSocket>();
            this.EncryptionAlgorithm = client.Server != null ? client.Server.serverProperties.EncryptionAlgorithm : client.Properties.EncryptionAlgorithm;
            this.CompressionAlgorithm = client.Server != null ? client.Server.serverProperties.CompressionAlgorithm : client.Properties.CompressionAlgorithm;

            //generate the header encryption
            byte[] privKey = client.Server != null ? client.Server.serverProperties.ServerCertificate.NetworkKey : client.Properties.NetworkKey;

            PrivateSeed = privKey.Length >= 4 ? BitConverter.ToInt32(privKey, 0) : 0xBEEF;

            for (int i = 0; i < privKey.Length; i++)
                PrivateSeed += privKey[i];

            byte[] SaltKey = new byte[privKey.Length];
            Array.Copy(privKey, SaltKey, SaltKey.Length);

            for (int i = 0; i < SaltKey.Length; i++)
                SaltKey[i] += (byte)PrivateSeed;
            
            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(PrivateSeed, 5, ref encCode, ref decCode);
            this.HeaderEncryption = new WopEx(privKey, SaltKey, InitialVector, encCode, decCode, WopEncMode.GenerateNewAlgorithm, client.Server != null ? client.Server.serverProperties.Cipher_Rounds : client.Properties.Cipher_Rounds, false);

            WopEx.GenerateCryptoCode(PrivateSeed << 3, 15, ref encCode, ref decCode);
            this.PayloadEncryption = new WopEx(privKey, SaltKey, InitialVector, encCode, decCode, WopEncMode.Simple, client.Server != null ? client.Server.serverProperties.Cipher_Rounds : client.Properties.Cipher_Rounds, true);

            byte[] temp_iv = new byte[16];
            Array.Copy(InitialVector, temp_iv, 16);
            this.EncAES = new HwAes(privKey, temp_iv, 256, System.Security.Cryptography.CipherMode.CBC, System.Security.Cryptography.PaddingMode.PKCS7);

            this.headerConfuser = new HeaderConfuser(PrivateSeed);

            this.QuickLZ = new UnsafeQuickLZ();

            this.messageHandler = new MessageHandler((uint)PrivateSeed + 0x0FA453FB);
            this.messageHandler.AddMessage(typeof(MsgHandshake), "MAZE_HAND_SHAKE");
            this.messageHandler.AddMessage(typeof(MsgCreateConnection), "CREATE_CONNECTION");
            this.messageHandler.AddMessage(typeof(MsgCreateConnectionResponse), "CREATE_CONNECTION_RESPONSE");

            this.messageHandler.AddMessage(typeof(MsgInitOk), "INIT_OK");
            this.messageHandler.AddMessage(typeof(MsgGetNextId), "GET_NEXT_NUMBER");
            this.messageHandler.AddMessage(typeof(MsgGetNextIdResponse), "GET_NEXT_NUMBER_RESPONSE");

            Headers.RegisterHeader(typeof(SystemHeader));
            Headers.RegisterHeader(typeof(ConnectionHeader));
            Headers.RegisterHeader(typeof(RequestHeader));
        }

        internal void StartReceiver()
        {
            Handle.BeginReceive(this.Buffer, 0, this.Buffer.Length, SocketFlags.None, AynsReceive, null);
        }

        private void AynsReceive(IAsyncResult result)
        {
            int BytesTransferred = -1;
            try
            {
                BytesTransferred = Handle.EndReceive(result);

                SysLogger.Log("Received " + BytesTransferred, SysLogType.Network);

                if (BytesTransferred <= 0)
                {
                    this.Connected = false;
                    return;
                }
            }
            catch
            {
                this.Connected = false;
                return;
            }


            //let's check the certificate
            if (Client.Certificate != null)
            {
                if (Client.Certificate.ValidFrom > DateTime.Now)
                {
                    //we need to wait till the time is right
                    Client.Disconnect();
                    return;
                }
                if (Client.Certificate.ValidTo < DateTime.Now)
                {
                    //certificate is not valid anymore
                    Client.Disconnect();
                    return;
                }
            }

            this.LastPacketSW = Stopwatch.StartNew();
            ReadableDataLen += BytesTransferred;
            DataIn += (ulong)BytesTransferred;
            bool Process = true;

            while (Process)
            {
                if (ReceiveState == ReceiveType.Header)
                {
                    Process = ReadableDataLen >= HEADER_SIZE;
                    if (ReadableDataLen >= HEADER_SIZE)
                    {
                        lock (HeaderEncryption)
                        {
                            headerConfuser.Deobfuscate(ref Buffer, ReadOffset);
                            HeaderEncryption.Decrypt(Buffer, ReadOffset, HEADER_SIZE);
                        }

                        PayloadLen = BitConverter.ToUInt16(Buffer, ReadOffset);
                        CurPacketId = Buffer[ReadOffset + 2];
                        ConnectionId = BitConverter.ToUInt16(Buffer, ReadOffset + 3);
                        HeaderId = BitConverter.ToUInt16(Buffer, ReadOffset + 5);
                        FragmentId = Buffer[ReadOffset + 7];
                        HeaderChecksum = Buffer[ReadOffset + 8];
                        FragmentFullSize = (int)Buffer[ReadOffset + 9] | Buffer[ReadOffset + 10] << 8 | Buffer[ReadOffset + 11] << 16;
                        FeatureId = BitConverter.ToInt32(Buffer, ReadOffset + 12);

                        byte ReChecksum = 0; //re-calculate the checksum
                        ReChecksum += (byte)PayloadLen;
                        ReChecksum += FragmentId;
                        ReChecksum += CurPacketId;
                        ReChecksum += (byte)ConnectionId;
                        ReChecksum += (byte)HeaderId;
                        ReChecksum += (byte)FragmentFullSize;
                        ReChecksum += (byte)FeatureId;

                        if (ReChecksum != HeaderChecksum ||
                            FragmentFullSize > MAX_FRAGMENT_SIZE)
                        {
                            Disconnect();
                            return;
                        }

                        TotalReceived = HEADER_SIZE;
                        ReadableDataLen -= HEADER_SIZE;
                        ReadOffset += HEADER_SIZE;
                        ReceiveState = ReceiveType.Payload;
                    }
                }
                else if (ReceiveState == ReceiveType.Payload)
                {
                    Process = ReadableDataLen >= PayloadLen;
                    if (ReadableDataLen >= PayloadLen)
                    {
                        byte[] DecryptedBuffer = null;
                        int DecryptedBuffOffset = 0;
                        int DecryptedBuffLen = 0;

                        #region Encryption & Compression

                        if (EncAlgorithm.HwAES == (EncryptionAlgorithm & EncAlgorithm.HwAES))
                        {
                            lock (EncAES)
                            {
                                if (DecryptedBuffer != null)
                                {
                                    DecryptedBuffer = EncAES.Decrypt(DecryptedBuffer, DecryptedBuffOffset, DecryptedBuffLen);
                                }
                                else
                                {
                                    DecryptedBuffer = EncAES.Decrypt(Buffer, ReadOffset, PayloadLen);
                                }
                                DecryptedBuffLen = DecryptedBuffer.Length;
                            }
                        }
                        if (EncAlgorithm.WopEx == (EncryptionAlgorithm & EncAlgorithm.WopEx))
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
                        }

                        if (CompressionAlgorithm.QuickLZ == (this.CompressionAlgorithm & SecureSocketProtocol3.CompressionAlgorithm.QuickLZ))
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
                        }
                        #endregion

                        TotalReceived += PayloadLen;
                        //check if Fragments are being used for big packets
                        //we could improve the performance of Fragments by changing the buffer directly to the FragmentBuffer
                        bool ProcessPacket = true;
                        if (FragmentId > 0)
                        {
                            if (FragmentId != 1 && FragmentBuffer == null)
                            {
                                //strange client behavior
                                Disconnect();
                                return;
                            }

                            if (FragmentBuffer == null)
                            {
                                //first Fragment, let's initialize the buffer
                                FragmentBuffer = new byte[FragmentFullSize];
                                FragmentOffset = 0;
                            }

                            Array.Copy(DecryptedBuffer, DecryptedBuffOffset, FragmentBuffer, FragmentOffset, DecryptedBuffLen); //here it will decrease performance
                            FragmentOffset += DecryptedBuffLen;

                            bool LastFragment = (FragmentId & 128) == 128;

                            //Check LastFragment flag
                            if (LastFragment)
                            {

                            }
                            else
                            {
                                ProcessPacket = false;
                            }
                        }

                        if (ProcessPacket)
                        {
                            using (PayloadReader pr = new PayloadReader(FragmentBuffer != null ? FragmentBuffer : DecryptedBuffer))
                            {
                                if (FragmentBuffer == null)
                                    pr.Offset = DecryptedBuffOffset;

                                OperationalSocket OpSocket = null;
                                if (ConnectionId > 0)
                                {
                                    lock(OperationalSockets)
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
                                    uint MessageId = pr.ReadUInteger();
                                    IMessage message = OpSocket != null ? OpSocket.MessageHandler.HandleMessage(pr, MessageId) : messageHandler.HandleMessage(pr, MessageId);

                                    if (message != null)
                                    {
                                        message.RawSize = TotalReceived;
                                        message.Header = header;

                                        if (message.GetType() == typeof(MsgHandshake))
                                        {
                                            //we must directly process this message because if the handshake ends the keys will change
                                            //and if we will handle this message in a different thread the chances are that the next packet will be unreadable
                                            message.ProcessPayload(Client, null);
                                        }
                                        else
                                        {
                                            lock (SystemPackets)
                                            {
                                                SystemPackets.Enqueue(new SystemPacket(header, message, ConnectionId));
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    Disconnect();
                                    return;
                                }
                            }

                            //destroy FragmentBuffer if used
                            FragmentBuffer = null;
                            TotalReceived = 0;
                        }

                        PacketsIn++;
                        ReadOffset += PayloadLen;
                        ReadableDataLen -= PayloadLen;
                        ReceiveState = ReceiveType.Header;
                    }
                }
            }

            int len = ReceiveState == ReceiveType.Header ? HEADER_SIZE : PayloadLen;
            if (ReadOffset + len >= this.Buffer.Length)
            {
                //no more room for this data size, at the end of the buffer ?

                //copy the buffer to the beginning
                Array.Copy(this.Buffer, ReadOffset, this.Buffer, 0, ReadableDataLen);

                WriteOffset = ReadableDataLen;
                ReadOffset = 0;
            }
            else
            {
                //payload fits in the buffer from the current offset
                //use BytesTransferred to write at the end of the payload
                //so that the data is not split
                WriteOffset += BytesTransferred;
            }
            Handle.BeginReceive(this.Buffer, WriteOffset, Buffer.Length - WriteOffset, SocketFlags.None, AynsReceive, null);
        }

        /// <summary>
        /// Send data to the established connection
        /// </summary>
        /// <param name="Message">The data to send</param>
        /// <param name="Header">The Header to use for adding additional information</param>
        /// <param name="feature">The Feature that has been used for this Message</param>
        /// <param name="OpSocket">The OperationalSocket that has been used for this Message</param>
        internal void SendMessage(IMessage Message, Header Header, Feature feature = null, OperationalSocket OpSocket = null)
        {
            lock (SendLock)
            {
                if (Message == null)
                    throw new ArgumentException("Message cannot be null");
                if (Header == null)
                    throw new ArgumentException("Header cannot be null");

                uint messageId = OpSocket != null ? OpSocket.MessageHandler.GetMessageId(Message.GetType()) : messageHandler.GetMessageId(Message.GetType());
                byte[] SerializedHeader = Header.Serialize(Header);
                ushort HeaderId = OpSocket != null ? OpSocket.Headers.GetHeaderId(Header) : Headers.GetHeaderId(Header);

                if (SerializedHeader.Length >= MAX_FRAGMENT_SIZE)
                    throw new ArgumentException("Header length cannot be greater then " + (MAX_PAYLOAD / 2));

                using (OptimizedPayloadStream ms = new OptimizedPayloadStream(SerializedHeader, HeaderId, feature, OpSocket))
                {
                    ms.Write(BitConverter.GetBytes(messageId), 0, 4);

                    MemoryStream stream = ms.PayloadFrames[ms.PayloadFrames.Count - 1];

                    int ReservedPos = (int)stream.Position;
                    ms.Write(new byte[3], 0, 3); //reserve space

                    ms.WritingMessage = true;
                    Serializer.Serialize(ms, Message);
                    ms.WritingMessage = false;

                    using (PayloadWriter pw = new PayloadWriter(new MemoryStream(stream.GetBuffer())))
                    {
                        pw.Position = ReservedPos; //skip MessageId data
                        pw.WriteThreeByteInteger(ms.MessageLength);//Reserved Space + MessageId = 7
                    }
                    ms.Commit(this);

                    for (int i = 0; i < ms.PayloadFrames.Count; i++)
                    {
                        stream = ms.PayloadFrames[i];

                        lock (HeaderEncryption)
                        {
                            HeaderEncryption.Encrypt(stream.GetBuffer(), 0, HEADER_SIZE);

                            byte[] temp = stream.GetBuffer();
                            headerConfuser.Obfuscate(ref temp, ReadOffset);
                        }
                        /*lock (PayloadEncryption)
                        {
                            PayloadEncryption.Encrypt(stream.GetBuffer(), HEADER_SIZE, (int)stream.Length - HEADER_SIZE);
                        }*/

                        Handle.Send(stream.GetBuffer(), 0, (int)stream.Length, SocketFlags.None);
                    }
                }
            }
        }

        private void onSystemPacket(SystemPacket systemPacket)
        {
            ConnectionHeader ConHeader = systemPacket.Header as ConnectionHeader;
            if (ConHeader != null)
            {
                lock (OperationalSockets)
                {
                    OperationalSocket OpSocket = null;
                    if (OperationalSockets.TryGetValue(systemPacket.ConnectionId, out OpSocket))
                    {
                        Header header = ConHeader.DeserializeHeader(OpSocket);
                        if (header == null)
                        {
                            return;
                        }

                        OpSocket.onReceiveMessage(systemPacket.Message, header);
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
            mazeHandshake.ApplyKey(this.HeaderEncryption, key);
            mazeHandshake.ApplyKey(this.HeaderEncryption, salt);

            mazeHandshake.ApplyKey(this.PayloadEncryption, key);
            mazeHandshake.ApplyKey(this.PayloadEncryption, salt);
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

        /// <summary>
        /// This will request a random id from the server to use, a better way of getting a random number
        /// </summary>
        /// <returns>A random decimal number</returns>
        public long GetNextRandomLong()
        {
            decimal number = GetNextRandomDecimal();
            number %= long.MaxValue;
            return (int)number;
        }

        /// <summary>
        /// This will request a random id from the server to use, a better way of getting a random number
        /// </summary>
        /// <returns>A random decimal number</returns>
        public int GetNextRandomInteger()
        {
            decimal number = GetNextRandomDecimal();
            number %= int.MaxValue;
            return (int)number;
        }

        /// <summary>
        /// This will request a random id from the server to use, a better way of getting a random number
        /// </summary>
        /// <returns>A random decimal number</returns>
        public decimal GetNextRandomDecimal()
        {
            if (Client.IsServerSided)
            {
                return Client.Server.randomDecimal.NextDecimal();
            }

            lock (NextRandomIdLock)
            {
                int ReqId = 0;
                SyncObject SyncNextRandomId = RegisterRequest(ref ReqId);

                SendMessage(new MsgGetNextId(), new RequestHeader(ReqId, false));

                decimal response = SyncNextRandomId.Wait<decimal>(0, 30000);

                if (response == null)
                    throw new Exception("A time out occured");

                return response;
            }
        }

        public void Disconnect()
        {
            try
            {
                Handle.Close();
            }
            catch { }
        }
    }
}