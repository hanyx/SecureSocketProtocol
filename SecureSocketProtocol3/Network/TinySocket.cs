﻿using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
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

namespace SecureSocketProtocol3.Network
{
    public abstract class TinySocket
    {
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
        /// The checksum is all the information combined to a small hash of 1Byte
        /// 
        /// </summary>
        
        public const int MAX_PACKET_SIZE = (1024 * 1024) * 1; //1MB
        public const int START_BUFFER_SIZE = 1024; //1KB

        protected abstract void onReceiveHeader(byte[] Data, int Offset);
        protected abstract void onReceivePayload(byte[] Data, int Offset, int Length);
        protected abstract void onDisconnect();
        protected abstract void onSendMessage(byte[] Data, int Offset, int Length);

        //header info
        protected int PayloadLen = 0;
        protected byte[] PayloadHMAC = null;

        //receive info
        private int ReadOffset = 0;
        private int WriteOffset = 0;
        private int ReadableDataLen = 0;
        private int TotalReceived = 0;
        private byte[] Buffer = new byte[START_BUFFER_SIZE];
        private Socket socket;
        private ulong PacketsProcessed = 0;

        private ReceiveType ReceiveState = ReceiveType.Header;
        private SocketAsyncEventArgs asyncEventArgs;

        protected Connection _connection;

        private bool squidRemoveEnter = true;

        public int HEADER_SIZE //Headersize contains, length + hmac
        {
            get
            {
                int length = 3;
                if (_connection.Client.DataIntegrityLayer != null)
                {
                    length += _connection.Client.DataIntegrityLayer.FixedLength;
                }
                return length;
            }
        }

        public TinySocket(Socket socket)
        {
            this.socket = socket;
        }

        internal void StartReceiver()
        {
            socket.BeginReceive(this.Buffer, 0, this.Buffer.Length, SocketFlags.None, socket_BeginRecieve, null);
        }

        private void socket_BeginRecieve(IAsyncResult ar)
        {
            int BytesTransferred = 0;
            
            try
            {
                BytesTransferred = socket.EndReceive(ar);
            }
            catch (Exception ex)
            {
                //client disconnected etc
            }

            SysLogger.Log("Received " + BytesTransferred, SysLogType.Network);

            if (BytesTransferred <= 0)
            {
                onDisconnect();
                return;
            }

            bool Process = true;
            ReadableDataLen += BytesTransferred;

            while (Process)
            {
                if (ReceiveState == ReceiveType.Header)
                {
                    if ((Process = ReadableDataLen >= HEADER_SIZE))
                    {
                        //squid proxy enter skip, it only happens once in the first packet
                        //why does squid even send a enter...
                        if (PacketsProcessed == 0 && squidRemoveEnter && Buffer[ReadOffset] == 0x0D && Buffer[ReadOffset + 1] == 0x0A)
                        {
                            ReadableDataLen -= 2;
                            ReadOffset += 2;
                            squidRemoveEnter = false;
                            continue;
                        }

                        onReceiveHeader(Buffer, ReadOffset);

                        using (PayloadReader pr = new PayloadReader(Buffer))
                        {
                            pr.Position = ReadOffset;
                            PayloadLen = pr.ReadThreeByteInteger();

                            if (_connection.Client.DataIntegrityLayer != null)
                            {
                                PayloadHMAC = pr.ReadBytes(_connection.Client.DataIntegrityLayer.FixedLength);
                            }
                        }
                        
                        if (PayloadLen >= MAX_PACKET_SIZE ||
                            PayloadLen < 0)
                        {
                            onDisconnect();
                            return;
                        }

                        if (PayloadLen > Buffer.Length)
                        {
                            ResizeBuffer(PayloadLen);
                        }

                        TotalReceived = HEADER_SIZE;
                        ReadableDataLen -= HEADER_SIZE;
                        ReadOffset += HEADER_SIZE;
                        ReceiveState = ReceiveType.Payload;
                    }
                }
                else if (ReceiveState == ReceiveType.Payload)
                {
                    if ((Process = ReadableDataLen >= PayloadLen))
                    {
                        onReceivePayload(Buffer, ReadOffset, PayloadLen);

                        TotalReceived = 0;
                        ReadOffset += PayloadLen;
                        ReadableDataLen -= PayloadLen;
                        PacketsProcessed++;
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

            if (Buffer.Length - WriteOffset > 0)
            {
                int readLen = Buffer.Length - WriteOffset;

                try
                {
                    /*this.asyncEventArgs.SetBuffer(this.Buffer, WriteOffset, Buffer.Length - WriteOffset);
                    if (!socket.ReceiveAsync(asyncEventArgs))
                    {
                        AsyncEventArgs_Completed(sender, asyncEventArgs);
                    }*/

                    socket.BeginReceive(this.Buffer, WriteOffset, Buffer.Length - WriteOffset, SocketFlags.None, socket_BeginRecieve, null);
                }
                catch (Exception ex)
                {
                    onDisconnect();
                }
            }
            else
            {
                //Shoudln't be even possible... very strange
                onDisconnect();
            }
        }
        
        private void ResizeBuffer(int NewLength)
        {
            if (NewLength > MAX_PACKET_SIZE)
                NewLength = MAX_PACKET_SIZE;

            Array.Resize(ref Buffer, NewLength);
        }
    }
}