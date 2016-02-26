using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SecureSocketProtocol3.Security.Proxies
{
    public interface IProxy
    {
        bool Connect(Socket socket, IPEndPoint Proxy, IPEndPoint Destination);
    }
}