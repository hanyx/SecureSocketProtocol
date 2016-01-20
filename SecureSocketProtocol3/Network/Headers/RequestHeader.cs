using ProtoBuf;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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
    [ProtoContract]
    internal sealed class RequestHeader : Header
    {
        [ProtoMember(1)]
        public int RequestId;

        [ProtoMember(2)]
        public bool isResponse;

        public RequestHeader(int RequestId, bool isResponse)
            : base()
        {
            this.RequestId = RequestId;
            this.isResponse = isResponse;
        }
        public RequestHeader()
            : base()
        {

        }

        public override Version Version
        {
            get { return new Version(0, 0, 0, 1); }
        }

        public override string HeaderName
        {
            get { return "Request Response Header"; }
        }

        public void HandleResponse(SSPClient Client, object ResponseObj)
        {
            if (isResponse)
            {
                lock (Client.Connection.Requests)
                {
                    SyncObject syncObj = null;
                    if (Client.Connection.Requests.TryGetValue(RequestId, out syncObj))
                    {
                        syncObj.Value = ResponseObj;
                        syncObj.Pulse();
                        Client.Connection.Requests.Remove(RequestId);
                    }
                }
            }
        }
    }
}