using ProtoBuf;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Headers
{
    [ProtoContract]
    public class RequestHeader : Header
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
                    }
                }
            }
        }
    }
}