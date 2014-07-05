﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Diagnostics;
using SecureSocketProtocol3.Utils;
using System.IO;
using SecureSocketProtocol3.Encryptions;
using SecureSocketProtocol3.Network.Headers;

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
        /// </summary>
        public const int HEADER_SIZE = 8; //Headersize contains, length(USHORT) + CurPacketId(BYTE) + Connection Id(USHORT) + Header Id(USHORT) + Fragment (BYTE)
        public const int MAX_PAYLOAD = 65535 - HEADER_SIZE; //maximum size to receive at once, U_SHORT - HEADER_SIZE = 65529
        private const int FRAGMENT_MULTIPLIER = 3; //Multiply the size of the buffer by x, higher might improve performance but uses more memory

        public bool Connected { get; private set; }
        public decimal ClientId { get; internal set; }
        public SSPClient Client { get; private set; }
        private Socket Handle { get { return Client.Handle; } }
        private Stopwatch LastPacketSW = new Stopwatch();
        private byte[] Buffer = new byte[HEADER_SIZE + MAX_PAYLOAD];
        private SortedList<ushort, Type> Headers;

        private ReceiveType ReceiveState = ReceiveType.Header;

        //receive info
        private int ReadOffset = 0;
        private int WriteOffset = 0;
        private int ReadableDataLen = 0;

        //fragment information
        private byte[] FragmentBuffer = null;
        private int FragmentOffset = 0;


        //header info
        private int PayloadLen = 0;
        private byte CurPacketId = 0;
        private ushort ConnectionId = 0;
        private ushort HeaderId = 0;
        private byte FragmentId = 0;

        //Security
        private WopEx HeaderEncryption;

        //connection info
        public ulong PacketsIn { get; private set; }
        public ulong DataIn { get; private set; }
        public ulong PacketsOut { get; private set; }
        public ulong DataOut { get; private set; }

        Stopwatch sw = Stopwatch.StartNew();
        int recv = 0;
        int recvPackets = 0;
        int recvPacketsTotal = 0;

        public Connection(SSPClient client)
        {
            this.Client = client;
            this.Connected = true;
            this.Headers = new SortedList<ushort, Type>();
            RegisterHeader(typeof(SystemHeader));
            RegisterHeader(typeof(ConnectionHeader));

            //generate the header encryption
            byte[] privKey = client.Server != null ? client.Server.serverProperties.ServerCertificate.PrivateKey : client.Properties.PrivateKey;
            int seed = 0;
            for (int i = 0; i < privKey.Length; i++)
                seed += privKey[i];

            byte[] SaltKey = new byte[privKey.Length];
            Array.Copy(privKey, SaltKey, SaltKey.Length);

            for (int i = 0; i < SaltKey.Length; i++)
                SaltKey[i] += (byte)seed;
            
            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(seed, 25, ref encCode, ref decCode);
            this.HeaderEncryption = new WopEx(privKey, SaltKey, encCode, decCode, false);

            Handle.BeginReceive(this.Buffer, 0, this.Buffer.Length, SocketFlags.None, AynsReceive, null);
        }

        private void AynsReceive(IAsyncResult result)
        {
            int BytesTransferred = Handle.EndReceive(result);
            if (BytesTransferred <= 0)
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
                                FragmentBuffer = new byte[MAX_PAYLOAD * FRAGMENT_MULTIPLIER];
                                FragmentOffset = 0;
                            }

                            Array.Copy(Buffer, ReadOffset, FragmentBuffer, FragmentOffset, PayloadLen); //here it will decrease performance
                            FragmentOffset += PayloadLen;

                            bool LastFragment = (FragmentId & 128) == 128;

                            if (!LastFragment && FragmentOffset == FragmentBuffer.Length)
                            {
                                //here it will decrease performance
                                Array.Resize(ref FragmentBuffer, FragmentBuffer.Length + (MAX_PAYLOAD * FRAGMENT_MULTIPLIER));
                            }

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
                                if (Headers.TryGetValue(HeaderId, out type))
                                {
                                    Header header = Header.DeSerialize(type, pr);

                                    if (header.GetType() == typeof(SystemHeader))
                                    {

                                    }
                                    else if (header.GetType() == typeof(ConnectionHeader))
                                    {

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
        public void Send(byte[] data, int offset, int length, Header header)
        {
            if (header == null)
                throw new ArgumentException("Header cannot be null");

            byte fragment = (byte)(length > MAX_PAYLOAD ? 1 : 0);
            bool UseFragments = fragment > 0;

            //serialize the custom header
            byte[] SerializedHeader = Header.Serialize(header);
            ushort HeaderId = header.GetHeaderId(header);

            while(length > 0)
            {
                int packetLength = length > MAX_PAYLOAD ? MAX_PAYLOAD : length;
                byte[] tempBuffer = new byte[HEADER_SIZE + packetLength + SerializedHeader.Length];
                using (PayloadWriter pw = new PayloadWriter(new MemoryStream(tempBuffer, 0, tempBuffer.Length)))
                {
                    pw.Position = 0;

                    //header
                    pw.WriteUShort((ushort)(packetLength  + (SerializedHeader != null ? SerializedHeader.Length : 0))); //length
                    pw.WriteByte(CurPacketId); //cur packet id
                    pw.WriteUShort(0); //Connection Id
                    pw.WriteUShort(HeaderId); //Header Id

                    length -= packetLength;
                    if (UseFragments)
                    {
                        pw.WriteByte((byte)(length > 0 ? fragment : (fragment + 128))); //fragment id
                        fragment++;
                    }
                    else
                    {
                        pw.WriteByte(0); //fragment id
                    }

                    if (SerializedHeader != null)
                    {
                        pw.WriteBytes(SerializedHeader);
                    }

                    //encrypt the header
                    lock (HeaderEncryption)
                    {
                        HeaderEncryption.Encrypt(tempBuffer, 0, HEADER_SIZE);
                    }

                    //write data
                    pw.WriteBytes(data, offset, packetLength);
                    Handle.Send(tempBuffer, 0, pw.Position, SocketFlags.None);
                }
                offset += packetLength;
            }
        }

        private void RegisterHeader(Type HeaderType)
        {
            Header header = (Header)Activator.CreateInstance(HeaderType);
            ushort headerId = header.GetHeaderId(header);

            if (Headers.ContainsKey(headerId))
                throw new Exception("Header already exists, Header Conflict!");

            Headers.Add(headerId, HeaderType);
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