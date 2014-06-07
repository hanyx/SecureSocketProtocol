using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3
{
    public class ClientProperties
    {
        public string HostIp { get; private set; }
        public ushort Port { get; private set; }
        public int ConnectingTimeout;

        public ClientProperties(string HostIp, ushort Port, int ConnectingTimeout = 30000)
        {
            this.HostIp = HostIp;
            this.Port = Port;
            this.ConnectingTimeout = ConnectingTimeout;
        }
    }
}