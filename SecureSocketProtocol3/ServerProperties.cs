using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class ServerProperties
    {
        /// <summary> The port to listen at </summary>
        public abstract ushort ListenPort { get; }

        /// <summary> The local ip used to listen at, default: 0.0.0.0 </summary>
        public abstract string ListenIp { get; }
    }
}