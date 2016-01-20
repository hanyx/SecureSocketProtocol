using SecureSocketProtocol3.Security.DataIntegrity;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class ClientProperties
    {
        public abstract string HostIp { get; }
        public abstract ushort Port { get; }
        public abstract int ConnectionTimeout { get; }

        public abstract byte[] NetworkKey { get; }

        public ClientProperties()
        {

        }
    }
}