using SecureSocketProtocol3.Hashers;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Features
{
    public abstract class Feature
    {
        protected SSPClient Client { get; private set; }

        public Feature(SSPClient Client)
        {
            this.Client = Client;
        }

        public abstract void onBeforeConnect();
        public abstract void onConnect();
        public abstract void onDisconnect(DisconnectReason Reason);
        public abstract void onException(Exception ex, ErrorType errorType);

        public abstract Version Version { get; }
        public abstract string HeaderName { get; }

        public ushort GetFeatureId()
        {
            CRC32 hasher = new CRC32();
            uint name = BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(HeaderName)), 0);
            uint version = BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(Version.ToString())), 0);
            return (ushort)(name * version);
        }
    }
}