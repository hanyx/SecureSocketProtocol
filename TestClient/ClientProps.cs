using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TestClient
{
    public class ClientProps : ClientProperties
    {

        public override string HostIp
        {
            get
            {
                return "127.0.0.1";
            }
        }

        public override ushort Port
        {
            get { return 444; }
        }

        public override int ConnectionTimeout
        {
            get { return 30000; }
        }

        public override byte[] NetworkKey
        {
            get
            {
                return new byte[]
                {
                    80, 118, 131, 114, 195, 224, 157, 246, 141, 113,
                    186, 243, 77, 151, 247, 84, 70, 172, 112, 115,
                    112, 110, 91, 212, 159, 147, 180, 188, 143, 251,
                    218, 155
                };
            }
        }
    }
}
