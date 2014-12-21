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

        public abstract string Username { get; }
        public abstract string Password { get; }

        public abstract Stream[] PrivateKeyFiles { get; }
        public abstract Stream PublicKeyFile { get; }

        public abstract byte[] NetworkKey { get; }

        public abstract uint Cipher_Rounds { get; }

        public ClientProperties()
        {

        }


    }
}