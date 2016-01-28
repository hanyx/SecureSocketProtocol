using ExtraLayers.LZ4;
using ExtraLayers.LZMA;
using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.DataIntegrity;
using SecureSocketProtocol3.Security.Handshakes;
using SecureSocketProtocol3.Security.Layers;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using TestServer.Sockets;

namespace TestServer
{
    public class Peer : SSPClient
    {
        public Peer()
            : base()
        {

        }


        public override void onConnect()
        {
            Console.WriteLine("[" + DateTime.Now.ToString("HH:mm:ss") + "] User \"" + base.Username + "\" connected, Peer connected " + base.RemoteIp);
            //TestSocket testSock = new TestSocket(this);
            //testSock.Connect();
        }

        public override void onDisconnect(DisconnectReason Reason)
        {

        }

        public override void onException(Exception ex, ErrorType errorType)
        {
            Console.WriteLine(ex.Message);
        }

        public override void onBeforeConnect()
        {
            base.RegisterOperationalSocket(new TestSocket(this));

            //Timing configuration is enabled as default, just showing users it's there
            base.TimingConfiguration.Enable_Timing = true;
        }

        public override void onOperationalSocket_Connected(OperationalSocket OPSocket)
        {

        }

        public override void onOperationalSocket_BeforeConnect(OperationalSocket OPSocket)
        {

        }

        public override void onOperationalSocket_Disconnected(OperationalSocket OPSocket, DisconnectReason Reason)
        {

        }

        public override void onApplyLayers(LayerSystem layerSystem)
        {
            for (int i = 0; i < 1; i++)
            {
                //layerSystem.AddLayer(new Lz4Layer());
                //layerSystem.AddLayer(new LzmaLayer());
                //layerSystem.AddLayer(new QuickLzLayer());
                //layerSystem.AddLayer(new AesLayer(base.Connection));
                //layerSystem.AddLayer(new WopExLayer(5, 1, false, this));
            }
        }

        private IDataIntegrityLayer _dataIntegrityLayer;
        public override IDataIntegrityLayer DataIntegrityLayer
        {
            get
            {
                //return new CRC32Layer();
                if (_dataIntegrityLayer == null)
                    _dataIntegrityLayer = new HMacLayer(this);
                return _dataIntegrityLayer;
            }
        }

        public override void onApplyHandshakes(SecureSocketProtocol3.Security.Handshakes.HandshakeSystem handshakeSystem)
        {
            List<MemoryStream> keys = new List<MemoryStream>();
            keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey1.dat")));
            keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey2.dat")));
            Stream PublicKeyFile = new MemoryStream(File.ReadAllBytes(@".\Data\PublicKey1.dat"));

            MazeHandshake mazeHandshake = new MazeHandshake(this, new Size(128, 128), 5, 5);
            mazeHandshake.onFindUser += mazeHandshae_onFindUser;
            handshakeSystem.AddLayer(mazeHandshake);

            //handshakeSystem.AddLayer(new SslHandshake(this));
        }

        private User.UserDbInfo mazeHandshae_onFindUser(string EncryptedPublicKeyHash)
        {
            if (Program.Users.ContainsKey(EncryptedPublicKeyHash))
                return Program.Users[EncryptedPublicKeyHash];
            return null;
        }
    }
}