using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Diagnostics;
using SecureSocketProtocol3.Utils;
using System.IO;
using SecureSocketProtocol3.Encryptions;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Network.Messages.TCP;
using SecureSocketProtocol3.Misc;
using System.Threading;
using SecureSocketProtocol3.Network.MazingHandshake;

namespace SecureSocketProtocol3.Network
{
    public class Connection
    {
        internal static readonly byte[] VALIDATION = new byte[]
        {
            151, 221, 126, 222, 126, 142, 126, 208, 107, 209, 212, 218, 228, 167, 158, 252, 105, 147, 185, 178
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
        /// </summary>
        public const int HEADER_SIZE = 12; //Headersize contains, length(USHORT) + CurPacketId(BYTE) + Connection Id(USHORT) + Header Id(USHORT) + Fragment (BYTE) + Checksum(BYTE) + FragmentFullSize(3Bytes)
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
        internal SortedList<int, OperationalSocket> OperationalSockets { get; private set; }
        internal SortedList<int, SyncObject> Requests { get; private set; }

        private ReceiveType ReceiveState = ReceiveType.Header;
        internal SyncObject HandshakeSync { get; private set; }
        internal SyncObject InitSync { get; private set; }

        internal HeaderList Headers { get; private set; }
        
        //locks
        private object NextRandomIdLock = new object();

        //receive info
        private int ReadOffset = 0;
        private int WriteOffset = 0;
        private int ReadableDataLen = 0;

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

        //Security
        private WopEx HeaderEncryption;
        internal int PrivateSeed { get; private set; }

        //connection info
        public ulong PacketsIn { get; private set; }
        public ulong DataIn { get; private set; }
        public ulong PacketsOut { get; private set; }
        public ulong DataOut { get; private set; }

        Stopwatch sw = Stopwatch.StartNew();
        int recv = 0;
        int recvPackets = 0;
        int recvPacketsTotal = 0;

        internal bool HandShakeCompleted { get; set; }

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
            this.OperationalSockets = new SortedList<int, OperationalSocket>();

            //generate the header encryption
            byte[] privKey = client.Server != null ? client.Server.serverProperties.ServerCertificate.NetworkKey : client.Properties.NetworkKey;
            
            for (int i = 0; i < privKey.Length; i++)
                PrivateSeed += privKey[i];

            byte[] SaltKey = new byte[privKey.Length];
            Array.Copy(privKey, SaltKey, SaltKey.Length);

            for (int i = 0; i < SaltKey.Length; i++)
                SaltKey[i] += (byte)PrivateSeed;
            
            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(PrivateSeed, 25, ref encCode, ref decCode);
            this.HeaderEncryption = new WopEx(privKey, SaltKey, encCode, decCode, false, false);

            this.messageHandler = new MessageHandler((uint)PrivateSeed + 0x0FA453FB);
            this.messageHandler.AddMessage(typeof(MsgHandshake), "MAZE_HAND_SHAKE");
            this.messageHandler.AddMessage(typeof(MsgCreateConnection), "CREATE_CONNECTION");
            this.messageHandler.AddMessage(typeof(MsgCreateConnectionResponse), "CREATE_CONNECTION_RESPONSE");

            this.messageHandler.AddMessage(typeof(MsgInitOk), "INIT_OK");
            this.messageHandler.AddMessage(typeof(MsgGetNextId), "GET_NEXT_NUMBER");
            this.messageHandler.AddMessage(typeof(MsgGetNextIdResponse), "GET_NEXT_NUMBER_RESPONSE");
            this.messageHandler.AddMessage(typeof(MsgConnectionData), "CONNECTION_DATA");

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
                            HeaderEncryption.Decrypt(Buffer, ReadOffset, HEADER_SIZE);
                        }

                        PayloadLen = BitConverter.ToUInt16(Buffer, ReadOffset);
                        CurPacketId = Buffer[ReadOffset + 2];
                        ConnectionId = BitConverter.ToUInt16(Buffer, ReadOffset + 3);
                        HeaderId = BitConverter.ToUInt16(Buffer, ReadOffset + 5);
                        FragmentId = Buffer[ReadOffset + 7];
                        HeaderChecksum = Buffer[ReadOffset + 8];
                        FragmentFullSize = (int)Buffer[ReadOffset + 9] | Buffer[ReadOffset + 10] << 8 | Buffer[ReadOffset + 11] << 16;

                        byte ReChecksum = 0; //re-calculate the checksum
                        ReChecksum += (byte)PayloadLen;
                        ReChecksum += FragmentId;
                        ReChecksum += CurPacketId;
                        ReChecksum += (byte)HeaderId;
                        ReChecksum += (byte)FragmentFullSize;

                        if (ReChecksum != HeaderChecksum ||
                            FragmentFullSize > MAX_FRAGMENT_SIZE)
                        {
                            Disconnect();
                            return;
                        }

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

                            Array.Copy(Buffer, ReadOffset, FragmentBuffer, FragmentOffset, PayloadLen); //here it will decrease performance
                            FragmentOffset += PayloadLen;

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
                            using (PayloadReader pr = new PayloadReader(FragmentBuffer != null ? FragmentBuffer : this.Buffer))
                            {
                                if (FragmentBuffer == null)
                                    pr.Offset = ReadOffset;

                                Type type = null;
                                if ((type = Headers.GetHeaderType(HeaderId)) != null)
                                {
                                    Header header = Header.DeSerialize(type, pr);
                                    uint MessageId = pr.ReadUInteger();
                                    IMessage message = messageHandler.HandleMessage(pr, MessageId);
                                    message.RawSize = (FragmentBuffer != null ? FragmentBuffer.Length + (HEADER_SIZE * (FragmentId - 128)) : 0) + PayloadLen + HEADER_SIZE;
                                    message.Header = header;

                                    if (message.GetType() == typeof(MsgHandshake))
                                    {
                                        //we must directly process this message because if the handshake ends the keys will change
                                        //and if we will handle this message in a different thread the chances are that the next packet will be unreadable
                                        message.ProcessPayload(Client);
                                    }
                                    else
                                    {
                                        lock (SystemPackets)
                                        {
                                            SystemPackets.Enqueue(new SystemPacket(header, message));
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
        /// <param name="data">The data to send</param>
        /// <param name="offset">The index where the data starts</param>
        /// <param name="length">The length of the data to send</param>
        /// <param name="header">The header to use for adding additional information</param>
        private void _send(byte[] data, int offset, int length, Header header)
        {
            if (header == null)
                throw new ArgumentException("Header cannot be null");
            if (length >= MAX_FRAGMENT_SIZE)
                throw new ArgumentException("Data length cannot be greater then " + MAX_FRAGMENT_SIZE);

            //serialize the custom header
            byte[] SerializedHeader = Header.Serialize(header);
            ushort HeaderId = Headers.GetHeaderId(header);

            byte fragment = (byte)(length > MAX_PAYLOAD ? 1 : 0);
            bool UseFragments = fragment > 0;
            int FullLength = length + SerializedHeader.Length + (UseFragments ? 3 : 0);

            while(length > 0)
            {
                int packetLength = length > MAX_PAYLOAD ? MAX_PAYLOAD : length;
                byte[] tempBuffer = new byte[HEADER_SIZE + packetLength + (SerializedHeader != null ? SerializedHeader.Length : 0)];
                using (PayloadWriter pw = new PayloadWriter(new MemoryStream(tempBuffer, 0, tempBuffer.Length)))
                {
                    length -= packetLength;
                    pw.Position = 0;

                    ushort PayloadLength = (ushort)(packetLength + (SerializedHeader != null ? SerializedHeader.Length : 0));
                    byte FragmentId = UseFragments ? (byte)(length > 0 ? fragment : (fragment + 128)) : (byte)0;

                    //header
                    pw.WriteUShort(PayloadLength); //length
                    pw.WriteByte(CurPacketId); //cur packet id
                    pw.WriteUShort(0); //Connection Id
                    pw.WriteUShort(HeaderId); //Header Id

                    if (UseFragments)
                    {
                        pw.WriteByte(FragmentId); //fragment id
                        fragment++;
                    }
                    else
                    {
                        pw.WriteByte(0); //fragment id
                    }

                    byte checksum = 0;
                    checksum += (byte)PayloadLength;
                    checksum += FragmentId;
                    checksum += CurPacketId;
                    checksum += (byte)HeaderId;
                    checksum += (byte)FullLength;
                    pw.WriteByte(checksum);

                    pw.WriteThreeByteInteger(FullLength); //the full packet size, mainly used for Fragmentation

                    //encrypt the header
                    lock (HeaderEncryption)
                    {
                        HeaderEncryption.Encrypt(tempBuffer, 0, HEADER_SIZE);
                    }

                    //payload related
                    if (SerializedHeader != null)
                    {
                        pw.WriteBytes(SerializedHeader);
                        SerializedHeader = null; //only send the header once
                    }

                    //write data
                    pw.WriteBytes(data, offset, packetLength);
                    Handle.Send(tempBuffer, 0, pw.Position, SocketFlags.None);
                }
                offset += packetLength;
            }
        }

        private void onSystemPacket(SystemPacket systemPacket)
        {
            systemPacket.Message.ProcessPayload(Client);
        }

        internal void SendMessage(IMessage message, Header header)
        {
            using (PayloadWriter pw = new PayloadWriter())
            {
                pw.WriteUInteger(messageHandler.GetMessageId(message.GetType()));
                pw.WriteBytes(IMessage.Serialize(message));
                _send(pw.ToByteArray(), 0, pw.Length, header);
            }
        }

        internal void ApplyNewKey(Mazing mazeHandshake, byte[] key, byte[] salt)
        {
            mazeHandshake.ApplyKey(this.HeaderEncryption, key);
            mazeHandshake.ApplyKey(this.HeaderEncryption, salt);
        }

        internal SyncObject RegisterRequest(ref int RequestId)
        {
            lock (Requests)
            {
                SyncObject syncObj = new SyncObject(this);
                Random rnd = new Random();

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
                    throw new Exception("A time out occured, ");

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