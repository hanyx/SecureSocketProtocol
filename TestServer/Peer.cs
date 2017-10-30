using ExtraLayers.LZ4;
using ExtraLayers.LZMA;
using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.DataIntegrity;
using SecureSocketProtocol3.Security.Encryptions;
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
                layerSystem.AddLayer(new AesLayer(base.Connection));
                //layerSystem.AddLayer(new WopExLayer(5, 1, false, this));
                //layerSystem.AddLayer(new TwoFishLayer(base.Connection));
                //layerSystem.AddLayer(new RC4Layer());
                //layerSystem.AddLayer(new XmlHidingLayer());
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

        public override void onApplyHandshakes(HandshakeSystem handshakeSystem)
        {
            //to generate a new key...
            //RSAEncryption GenPrivateKeyc = new RSAEncryption(4096, true);
            //GenPrivateKeyc.GeneratePrivateKey();
            //string PreGenPrivateKey = GenPrivateKeyc.PrivateKey;

            //use the top RSA Private Key to give the user an error that the fingerprint no longer matches
            string PrePrivKey = /*@"<RSAKeyValue>
                                        <Modulus>0K5LL5yYMf8mbVvJv1UoigbkON4SAUjQysTb74Z/NQR9qNs3xPrs9zqTWjDTLoHHTVC2JHZMpPBYAJJquz+7LpGm5HEOhsuB8d/gEMf4Jkazo+pOq0O9vJNqyoOx8qKJrVCv7FYJFD4Vl2BbiY67NsvRkHU418C+qW8QZ8rLkRTc4VQufFGwhhttoOUTav9qVZ2VDrTEH8wxHqJWBDmJw7D91UwIoIJCss0tclBQhujMqq94vEz2yOXi2jZTBzi+4WxTkLNFIA2/w1dJbz2+1DsV5bfgBLZDxR4HjBYoZ89VrvFhSUrZBghLeujGYqW33V3Q8nLnCJATH9ZpXAxLildZf1pBKSKSTshx3esp4F2clSxYNZZ8LXxz24lPcDYVvoc0oGUWmMiHX8+zvc6g430EVOIKS7tRUhOL06oIykqlu8hMURiMMole2t7gR+zlD/KvDI9v984p6edOaZ4yXuR5C8gNFqZv9rOyxdLjXEH57j8k60skxbu2V4zgprNuVxnMYIrFc5M2PrOzpZUegNIeYsiE6N8SIrcC7haTduGSDlStWEjYpqtRMtEOC1y23GtMz6YL1vpovNwsBVfqWLPHIcFxjplq3laJs5WV4XMjNiZ3T3ZGtiF9JAuYYUd4Oe3E3AGUUWi88RCmBJSHmOB5Lm3tgP2PtPZSCuTbISs=</Modulus>
                                        <Exponent>AQAB</Exponent>
                                        <P>6jrM9r5AA0q7DpQg0JQYAcyKymPLc+Qm/ztu7DzLdW1LNHHWlSdwd/wlXAmPSFlgjgs3UyPOZpokHUUZuviW5VDAPV75BVozytPAkD1OcUd/KPznCLj9+CEZMLs+5oTyWXVUiSmWY87ii5Vu7DfVATuuM+LcOqfN2Yf4jMKzJcofsnsbZE5LZv4QM5AKyHEYlBiZ6NGsKiOz5zaNMETBleiRF9B4LDhdzULXF8CtzZzSi0icaxOZxqcGtgcyLhwby1bripburLNssn3/WTLwbiguVDoH/cTDtalAnqyXG5OVco6qCrhFLzigm03yHEGBVYIq2GNK5xI+suY0AXXPUw==</P>
                                        <Q>5BOXIL7SIcSxYDjHE2gSlozahkpLqgSwO7/Akj2RFXQYk3dgvvNlo/ZxpjTCqQP173NNPdrlv4s+9gO81l/MRpLyb/FVZhvzO16G1tAeQ079RU45cM4azEeL2XcZ7H0P31U3ihvAlQjZ8sSepYnsWjAtcBRT/+CAcXigJjDdQy+RMG5SkiPWemQeMcBYavbrF7CvzlwYOJRnNSdxKMFH1zyWmmZu261ZK3/Zt8y2ga8GOj8rjZgsichSJe+P09ExMqNOc/Is0y9u5ZaIz5ct2YZNyLJfX2julHwlK5wWABFkpxUKqGfPb+T5zjprKcOduqCQysXMQIVad4TOMpEjyQ==</Q>
                                        <DP>F8N5cfshUXQugC8lGSQ9P0l6N0hiptJZ5oEoIs2UMsiw3ZRDGgTTU0kAnVLW95chxad7qHK0iRJQYavWDXMVFBTaPB+7kgBxyr0rBzdBExsW2pi189uY4Kiy/o+wtQB9+fd+aSAQAvZFY7X4d/y+Ho7ogJkekNDfgJdb7yP9uvLDvn7g649J9RwHlsOhZG6c+MF6M/W5ytiucuHE90WygjwDJHBhENNzKNUEL4O73mVvsvPd8rsdWdsuQh9+xtDRPRMHeJsRgfH+MCm6U1lorTRkZuUwVF23IWIXjUGjXwfdHK8+rzG8yyqqmLcSvi0jKwK2yBdizQi71binRBKoww==</DP>
                                        <DQ>mu9T8sKuLJJZjGwFkIFaXztAF4nQ7KZSscQJJU79h/1d1I98ATuHCGMZwTaGJhqyrv88sZBKElydYLIZTee19RtN5g2jXcIO8X29S6AFbuPx2WrSSnc4bR0NO6VUzvoGFkjlecRwhs2EgQ5gV0Pic0HXHBQzG9d+aZbv9AGtzT46+xN2tB/0SyBIArQPXFpwSZ+VTjHxoj3t/oXUsULbcrON+0UqecDAmnQ3ikxejqo/KMJQ69c8Kj0S0QJ0SggJy8R0Pv98w9mtE/m25o5kbyh1HqlNcJrvt56+AWn+5/zoyzfYDZ63o+OAbz/wHGbudyEsOxMzNYFhe1+UU3WVQQ==</DQ>
                                        <InverseQ>w9Wbzzz+Hi5tlZyQYLouDqgFrDNueFHyS4dNd3vIwSHfRPzj9Tv1XC/1Z6J8en9FF/O46HwZCsWnpSAl9ezaxoaKMWEw/J0td+jwaXxH+qzxh/q/kPAnq/2oG9nH1wnUOoGYkChvOxT0S7PLYMOVRvePHYc6C3EY4aZhhAaDfeKmUyShmW59yMBqXUfcPlX6cZc04059wvOhHCfcPDThLbcD/HoQEs9DNWyn38bJzP8Di5NTaWEvYkJfdOjEqXUanCmxHPqr2oVmX/MyQhHUAGVNS1zR6h4vU/iV6RcVie8FcOcL1BMWde/1/7cltzgd/XYyrGAVAamZD8+EPuaTGA==</InverseQ>
                                        <D>Npr1B59lX+fRKVqUXyGsevm0rIDHm1hvci+zEWlTTg8/xniejkfOzB6iwj32dLv25+9Pyhi+k4ZksLmffiH+HAB2+F3xHCqSdTVMz3dUIsfrZ9/+9+fA9WBp2FY/sSsA9b4gWqpks8xPIA5RxZv4tyz8SF20IxjHi1SJqW8yd2NLLRc3FsbVdzIkLK7ktuHg9EhI4dFBZMSsscRu16oqt29P7Il51G5hf6Ia20fS2op+S8egwz0scoNdKhZ/AWvC3v/Wmg2e7/VJEZd8msRAdA6F+1dzIiiDcUgbV3fQ2OEzHZUCDQit41s2TRIuH1AX3bAX5elVNTNmHbWgWjrJZQ/fPSHqZ82sewhUFyDnwCG/I/3J9TE99JsrNXGcMgphp8FYvUR5bIZ2ZFkG+dOrQnD2lf0vGForZd3eqZXVSxaMVY+fFCAwnZCUkH4RSdXhEc7ZysQs7HgD/74QAwD4RbeS8M3gWvLU255r+cLpRTxBPvMmM0X0e3idxjQGSwfuoDPKjQltB/qNcDri1FL3SqZGLEoSUHTNpiG8OROTt2l4uZ0XeykwqLJDghdcj9n9/7VX6ltewN2JabZ4OYd9sJvA44BoDP5ITdeCl3tfklGDuM6Yb4Vpu0yVJC646X9yRsh+aGeqGOH1dNpD8yyjDbcLd/xBCyS3SKbBbM/ApdE=</D>
                                    </RSAKeyValue>";*/
                @"<RSAKeyValue>
                                    <Modulus>ui7rEnh9ovwwe1c8CRthTOqnjB9EjoPgeiBL1291sXpOf0XPhHP+melBzr0yx2rSgTvgGboSFUjNQn6cxGwWklObZHs+kWev1uz2QgDC/j41es9bmLtH2P+AEFAXb1DhYSiLA/USaRyQ+LZqPdpb/euWofXuIcb2y+R8vtVVFkU=</Modulus>
                                    <Exponent>AQAB</Exponent>
                                    <P>zWiN6Zu6BfYrIgnYNyO5JTSEWfM689ovwL/agFW8uadmJOzeCeprrjGf8kyjcxVljw2om9Vw/H4ZcN0HR7YShw==</P>
                                    <Q>6AotVwrrC0E/+x5KOpp1fsl1zTHBdIMzsbwds1Ym1L3JHlstkNP8DejfxH9Ej2sYttLogJ5g5Ra781d2WxTn0w==</Q>
                                    <DP>InhnSEq/3vw+pMmuJSKzkVDM3SN6Qy3cUaZgjqTUtPsoow20/Uj/pQ3i35CI5Wkzz9vk7bHV8ilfL5eH/zrIxQ==</DP>
                                    <DQ>GJ4jy01MPIhyqki/ZVJHzui+x8NUm/DjhiLIH+OvAPkVolPYFLp4zlz7iJRcCL87AwKDSkoDS6rKy/lmhClGow==</DQ>
                                    <InverseQ>BSTKfqQr8WqrvOGWqmK8PupDfvI9d7u8UYJEpsAfEJFoSpTpG/WmSePBut0ukki3/qOeaOqULItu5XNnthtkPw==</InverseQ>
                                    <D>I8CowYZD0g2NndHVpIYOfD+/ZugGOTvX2nvjNH6h4i/zbPtR60R/Cr1BNtscKjE4NTrzQN17ZXzydadsoUeEWccVVdH7pJXCUCm6klLbgKZDrEAhJInDnkkzFRI4EMGLKeW1o41s/kqw1XF4zVFDRFLlEH1CwJ7y3ewqc+KppM0=</D>
                                  </RSAKeyValue>";

            handshakeSystem.AddLayer(new SimpleRsaHandshake(this, PrePrivKey));



            List<MemoryStream> keys = new List<MemoryStream>();
            keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey1.dat")));
            keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey2.dat")));
            Stream PublicKeyFile = new MemoryStream(File.ReadAllBytes(@".\Data\PublicKey1.dat"));

            //MazeHandshake mazeHandshake = new MazeHandshake(this, new Size(128, 128), 5, 1);
            //mazeHandshake.onFindUser += mazeHandshae_onFindUser;
            //handshakeSystem.AddLayer(mazeHandshake);
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