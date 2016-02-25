using SecureSocketProtocol3;
using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.IO;
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

        public override SecureSocketProtocol3.Security.Serialization.ISerialization DefaultSerializer
        {
            get
            {
                return new ProtobufSerialization();
            }
        }

        public override System.IO.Stream[] KeyFiles
        {
            get
            {
                List<MemoryStream> _keyFiles = new List<MemoryStream>();
                _keyFiles.Add(new MemoryStream(new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 }));
                _keyFiles.Add(new MemoryStream(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }));
                return _keyFiles.ToArray();
            }
        }
    }
}