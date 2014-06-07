using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Diagnostics;
using SecureSocketProtocol3.Utils;
using System.IO;

namespace SecureSocketProtocol3.Network
{
    public class Connection
    {
        internal static readonly byte[] VALIDATION = new byte[]
        {
            151, 221, 126, 222, 126, 142, 126, 208, 107, 209, 212, 218, 228, 167, 158, 252, 105, 147, 185, 178
        };

        public const int HEADER_SIZE = 6; //Headersize contains, length(USHORT) + CurPacketId(BYTE) + Connection Id(USHORT) + Header Id(BYTE)
        public const int MAX_PAYLOAD = 65529; //maximum size to receive at once, U_SHORT - HEADER_SIZE = 65529

        public bool Connected { get; private set; }
        public decimal ClientId { get; internal set; }
        public SSPClient Client { get; private set; }
        private Socket Handle { get { return Client.Handle; } }
        private Stopwatch LastPacketSW = new Stopwatch();
        private byte[] Buffer = new byte[HEADER_SIZE + MAX_PAYLOAD];

        private ReceiveType ReceiveState = ReceiveType.Header;

        //receive info
        private int ReadOffset = 0;
        private int WriteOffset = 0;
        private int ReadableDataLen = 0;

        //header info
        private int PayloadLen = 0;
        private byte CurPacketId = 0;
        private ushort ConnectionId = 0;
        private byte HeaderId = 0;

        Stopwatch sw = Stopwatch.StartNew();
        int recv = 0;
        int recvPackets = 0;
        int recvPacketsTotal = 0;

        public Connection(SSPClient client)
        {
            this.Client = client;
            Handle.BeginReceive(this.Buffer, 0, this.Buffer.Length, SocketFlags.None, AynsReceive, null);
        }

        private void AynsReceive(IAsyncResult result)
        {
            int BytesTransferred = Handle.EndReceive(result);

            this.LastPacketSW = Stopwatch.StartNew();
            ReadableDataLen += BytesTransferred;
            bool Process = true;

            while (Process)
            {
                if (ReceiveState == ReceiveType.Header)
                {
                    Process = ReadableDataLen >= HEADER_SIZE;
                    if (ReadableDataLen >= HEADER_SIZE)
                    {
                        PayloadLen = BitConverter.ToUInt16(Buffer, ReadOffset);
                        CurPacketId = Buffer[ReadOffset + 2];
                        ConnectionId = BitConverter.ToUInt16(Buffer, ReadOffset + 3);
                        HeaderId = Buffer[ReadOffset + 5];



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
                        

                        recvPackets++;
                        recvPacketsTotal++;
                        ReadOffset += PayloadLen;
                        ReadableDataLen -= PayloadLen;
                        ReceiveState = ReceiveType.Header;
                    }
                }
            }

            int len = ReceiveState == ReceiveType.Header ? HEADER_SIZE : PayloadLen;
            if (ReadOffset + len >= this.Buffer.Length)
            {
                //no more room for this payload size, at the end of the buffer ?

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

        public void Send(byte[] data, int offset, int length)
        {
            byte[] tempBuffer = new byte[HEADER_SIZE + length];
            using (PayloadWriter pw = new PayloadWriter(new MemoryStream(tempBuffer, 0, tempBuffer.Length)))
            {
                //header
                pw.WriteUShort((ushort)length);
                pw.WriteByte(CurPacketId);
                pw.WriteUShort(43221);
                pw.WriteByte(131);



                //write data
                pw.WriteBytes(data, offset, length);

                Handle.Send(tempBuffer, 0, tempBuffer.Length, SocketFlags.None);
            }
        }
    }
}