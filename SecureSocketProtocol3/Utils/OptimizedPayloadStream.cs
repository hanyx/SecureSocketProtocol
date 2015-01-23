using SecureSocketProtocol3.Compressions;
using SecureSocketProtocol3.Features;
using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol3.Utils
{
    /// <summary>
    /// This Stream is meant to optimize the memory usage and to gain performance
    /// </summary>
    internal class OptimizedPayloadStream : Stream
    {
        public List<MemoryStream> PayloadFrames { get; private set; }
        private long _length;

        private byte[] SerializedHeader;
        private ushort HeaderId;

        public bool WritingMessage { get; set; }
        public int MessageLength { get; private set; }

        public Feature feature { get; private set; }
        public OperationalSocket OpSocket { get; private set; }

        public OptimizedPayloadStream(byte[] SerializedHeader, ushort HeaderId,
                                      Feature feature = null, OperationalSocket OpSocket = null)
            : base()
        {
            this.PayloadFrames = new List<MemoryStream>();
            this.SerializedHeader = SerializedHeader;
            this.HeaderId = HeaderId;
            this.feature = feature;
            this.OpSocket = OpSocket;
        }

        public override bool CanRead
        {
            get { return false; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override void Flush()
        {

        }

        public override long Length
        {
            get { return _length; }
        }

        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _length += count;

            if (WritingMessage)
                MessageLength += count;

            while (count > 0)
            {
                MemoryStream Stream = null;

                if (PayloadFrames.Count == 0)
                    Stream = CreateStream(); //create new Stream if there is none yet
                else if (PayloadFrames.Count > 0 && PayloadFrames[PayloadFrames.Count - 1].Length == 65535)
                    Stream = CreateStream(); //create new Stream if it's full
                else if (PayloadFrames.Count > 0 && PayloadFrames[PayloadFrames.Count - 1].Length + count < 65535)
                    Stream = PayloadFrames[PayloadFrames.Count - 1]; //write to existing Stream since it's half full
                else if (PayloadFrames.Count > 0)
                {
                    //when hitting this most likely we're about to write big data
                    Stream = PayloadFrames[PayloadFrames.Count - 1];
                }

                int WriteLength = Stream.Length + count > 65535 ? 65535 - (int)Stream.Length : count;

                Stream.Write(buffer, offset, WriteLength);
                offset += WriteLength;
                count -= WriteLength;
            }
        }

        private MemoryStream CreateStream()
        {
            MemoryStream ms = new MemoryStream();

            //at commit we will fill the reserved space with the Header Information
            ms.Write(new byte[Connection.HEADER_SIZE], 0, Connection.HEADER_SIZE);

            if (PayloadFrames.Count == 0)
            {
                ms.Write(SerializedHeader, 0, SerializedHeader.Length);
            }

            PayloadFrames.Add(ms);
            return ms;
        }

        /// <summary>
        /// Save the changes and apply Header Information
        /// </summary>
        public void Commit(Connection conn)
        {
            bool UseFragments = PayloadFrames.Count > 1;
            int FullLength = 0;
            byte FragmentId = (byte)(UseFragments ? 1 : 0);

            //count all the payload, this is the original size
            for (int i = 0; i < PayloadFrames.Count; i++)
                FullLength += (int)PayloadFrames[i].Length - Connection.HEADER_SIZE;

            #region Encryption & Compression
            //compress all the data
            for (int i = 0; i < PayloadFrames.Count; i++)
            {
                MemoryStream stream = PayloadFrames[i];
                if (CompressionAlgorithm.QuickLZ == (conn.CompressionAlgorithm & CompressionAlgorithm.QuickLZ))
                {
                    UnsafeQuickLZ quickLz = new UnsafeQuickLZ();
                    byte[] compressed = quickLz.compress(stream.GetBuffer(), (uint)Connection.HEADER_SIZE, (uint)stream.Length - Connection.HEADER_SIZE);

                    if (compressed != null)
                    {
                        stream.Position = Connection.HEADER_SIZE;
                        stream.Write(compressed, 0, compressed.Length);

                        if (stream.Length != compressed.Length + Connection.HEADER_SIZE)
                            stream.SetLength(compressed.Length + Connection.HEADER_SIZE);
                    }
                }
            }

            //encrypt all the data
            for (int i = 0; i < PayloadFrames.Count; i++)
            {
                MemoryStream stream = PayloadFrames[i];
                if (EncAlgorithm.HwAES == (conn.EncryptionAlgorithm & EncAlgorithm.HwAES))
                {
                    lock (conn.EncAES)
                    {
                        //no need to re-size the stream here, AES will encrypt at the same size or bigger then the stream, so data will be overwritten
                        byte[] encrypted = conn.EncAES.Encrypt(stream.GetBuffer(), Connection.HEADER_SIZE, (int)stream.Length - Connection.HEADER_SIZE);
                        stream.Position = Connection.HEADER_SIZE;
                        stream.Write(encrypted, 0, encrypted.Length);
                    }
                }
                if (EncAlgorithm.WopEx == (conn.EncryptionAlgorithm & EncAlgorithm.WopEx))
                {
                    lock (conn.PayloadEncryption)
                    {
                        conn.PayloadEncryption.Encrypt(stream.GetBuffer(), Connection.HEADER_SIZE, (int)stream.Length - Connection.HEADER_SIZE);
                    }
                }
            }
            #endregion

            for (int i = 0; i < PayloadFrames.Count; i++)
            {
                PayloadWriter pw = new PayloadWriter(PayloadFrames[i]);
                pw.Position = 0;

                //if (pw.Length - Connection.HEADER_SIZE > ushort.MaxValue)
                //    throw new OverflowException(); //should never happen if Write(...) is handled correctly

                ushort PayloadLength = (ushort)(pw.Length - Connection.HEADER_SIZE);

                byte CurPacketId = 0;
                int FeatureId = feature != null ? feature.GetFeatureId() : -1;
                ushort ConnectionId = OpSocket != null ? OpSocket.ConnectionId : (ushort)0;

                if (i + 1 >= PayloadFrames.Count && UseFragments)
                    FragmentId += 128;

                byte checksum = 0;
                checksum += (byte)PayloadLength;
                checksum += FragmentId;
                checksum += CurPacketId;
                checksum += (byte)ConnectionId;
                checksum += (byte)HeaderId;
                checksum += (byte)FullLength;
                checksum += (byte)FeatureId;

                pw.WriteUShort(PayloadLength); //length
                pw.WriteByte(CurPacketId); //cur packet id
                pw.WriteUShort(ConnectionId); //Connection Id
                pw.WriteUShort(HeaderId); //Header Id
                pw.WriteByte(FragmentId);
                pw.WriteByte(checksum);
                pw.WriteThreeByteInteger(FullLength); //the full packet size, mainly used for Fragmentation
                pw.WriteInteger(FeatureId);

                if (UseFragments)
                    FragmentId++;
            }
        }
    }
}