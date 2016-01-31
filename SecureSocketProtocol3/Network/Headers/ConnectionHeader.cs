using ProtoBuf;
using System;
using System.Collections.Generic;
using System.IO;
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

namespace SecureSocketProtocol3.Network.Headers
{
    /// <summary>
    /// The header information for establishing a connection
    /// </summary>
    [ProtoContract]
    internal sealed class ConnectionHeader : Header
    {
        public override Version Version
        {
            get { return new Version(0, 0, 0, 3); }
        }

        public override string HeaderName
        {
            get { return "Connection Header"; }
        }

        [ProtoMember(1)]
        public byte[] HeaderPayload;

        [ProtoMember(2)]
        public ushort HeaderPayloadId;

        [ProtoMember(3)]
        public int FeatureId;

        public ConnectionHeader(Header header, OperationalSocket OpSocket, int FeatureId)
            : base()
        {
            this.HeaderPayload = Headers.Header.Serialize(header);

            this.HeaderPayloadId = OpSocket.Headers.GetHeaderId(header);
            this.FeatureId = FeatureId;
        }

        public ConnectionHeader()
            : base()
        {

        }

        public Header DeserializeHeader(OperationalSocket OpSocket)
        {
            Type HeaderType = OpSocket.Headers.GetHeaderType(HeaderPayloadId);
            if(HeaderType == null)
                return null;
            return Headers.Header.DeSerialize(HeaderType, new Utils.PayloadReader(HeaderPayload));
        }
    }
}