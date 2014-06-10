using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class ClientProperties
    {
        public abstract string HostIp { get; }
        public abstract ushort Port { get;  }
        public abstract int ConnectionTimeout { get; }
        public abstract byte[] PrivateKey { get; }

        public abstract string Username { get; }
        public abstract string Password { get; }

        public abstract Stream[] KeyFiles { get; }

        public ClientProperties()
        {

        }


    }
}