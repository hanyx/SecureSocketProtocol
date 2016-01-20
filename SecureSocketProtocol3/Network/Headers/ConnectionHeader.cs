using ProtoBuf;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/*
    Secure Socket Protocol
    Copyright (C) 2016 AnguisCaptor

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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