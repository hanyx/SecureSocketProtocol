using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SecureSocketProtocol3.Security.DataIntegrity;
using SecureSocketProtocol3.Security.Handshakes;
using SecureSocketProtocol3.Security.Layers;
using SecureSocketProtocol3.Security.Serialization;

namespace SSPTests.ServerSrc
{
    public class BasicPeer : SSPClient
    {

        public BasicPeer()
            : base()
        {

        }
        public BasicPeer(string IP, ushort Port)
            : base(new ClientProps(IP, Port))
        {

        }

        public override void onConnect()
        {

        }

        public override void onDisconnect(DisconnectReason Reason)
        {

        }

        public override void onException(Exception ex, ErrorType errorType)
        {

        }

        public override void onBeforeConnect()
        {

        }

        public override void onOperationalSocket_BeforeConnect(SecureSocketProtocol3.Network.OperationalSocket OPSocket)
        {

        }

        public override void onOperationalSocket_Connected(SecureSocketProtocol3.Network.OperationalSocket OPSocket)
        {

        }

        public override void onOperationalSocket_Disconnected(SecureSocketProtocol3.Network.OperationalSocket OPSocket, DisconnectReason Reason)
        {

        }

        public override void onApplyLayers(LayerSystem layerSystem)
        {

        }

        public override void onApplyHandshakes(HandshakeSystem handshakeSystem)
        {

        }

        public override IDataIntegrityLayer DataIntegrityLayer
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public class ClientProps : ClientProperties
        {
            private string _hostIp;
            private ushort _port;

            public ClientProps(string HostIp, ushort Port)
            {
                this._hostIp = HostIp;
                this._port = Port;
            }

            public override string HostIp
            {
                get { return _hostIp; }
            }

            public override ushort Port
            {
                get { return _port; }
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
}