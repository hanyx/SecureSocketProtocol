using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Security.Handshakes
{
    public class SimpleRsaHandshake : Handshake
    {
       /*
        * 1. Server sends out the Public Key to the client
        * 2. Client will check FingerPrint if it matches the server cert (human-check)
        * 3. Client will send a random 32-byte key to the Server (Encrypted with the Public Key)
        * 4. Client will apply the new key
        * 5. Server receives the message, decrypts it with the Private Key
        * 6. Server applies new key
        */


        public delegate bool FingerPrintCheckCallback(byte[] PublicKey, string Md5FingerPrint, string Sha512FingerPrint);
        public event FingerPrintCheckCallback onVerifyFingerPrint;

        private RSACryptoServiceProvider RsaCrypto = new RSACryptoServiceProvider();

        /// <summary>
        /// This constructor is used by the Client
        /// </summary>
        /// <param name="Client"></param>
        public SimpleRsaHandshake(SSPClient Client)
            : base(Client)
        {

        }

        /// <summary>
        /// Initialize the Server handshake
        /// </summary>
        /// <param name="Client"></param>
        /// <param name="PrivateKeyParams">The private key to use</param>
        public SimpleRsaHandshake(SSPClient Client, RSAParameters PrivateKeyParams)
            : base(Client)
        {
            RsaCrypto.ImportParameters(PrivateKeyParams);
        }

        /// <summary>
        /// Initialize the Server handshake
        /// </summary>
        /// <param name="Client"></param>
        /// <param name="PrivateKeyParams">The private key to use in XML format</param>
        public SimpleRsaHandshake(SSPClient Client, string PrivateKeyXML)
            : base(Client)
        {
            RsaCrypto.FromXmlString(PrivateKeyXML);
        }

        public override void onStartHandshake()
        {
            base.Client.MessageHandler.AddMessage(typeof(PublicKeyMessage), "RSA_PUBLIC_KEY_MESSAGE");
            base.Client.MessageHandler.AddMessage(typeof(KeyReplyMessage), "RSA_REPLY_KEY_MESSAGE");

            if (base.Client.IsServerSided)
            {
                base.SendMessage(new PublicKeyMessage(RsaCrypto, RsaCrypto.ExportParameters(false)), new NullHeader());
            }
        }

        public override void onReceiveMessage(Network.Messages.IMessage Message)
        {
            PublicKeyMessage publicMessage = Message as PublicKeyMessage;
            KeyReplyMessage replyKeyMessage = Message as KeyReplyMessage;

            if (publicMessage != null)
            {
                RSAParameters PublicParams = new RSAParameters();
                PublicParams.Exponent = publicMessage.Exponent;
                PublicParams.Modulus = publicMessage.Modulus;
                RsaCrypto.ImportParameters(PublicParams);

                //Verify the data
                if (!RsaCrypto.VerifyData(publicMessage.Modulus, new SHA512CryptoServiceProvider(), publicMessage.SignedData))
                {
                    base.Client.Disconnect();
                    return;
                }

                if(onVerifyFingerPrint != null)
                {
                    string md5fingerPrint = Convert.ToBase64String(publicMessage.Modulus);
                    md5fingerPrint = BitConverter.ToString(MD5.Create().ComputeHash(ASCIIEncoding.ASCII.GetBytes(md5fingerPrint)));
                    md5fingerPrint = md5fingerPrint.Replace('-', ':');

                    string shafingerPrint = Convert.ToBase64String(publicMessage.Modulus);
                    shafingerPrint = BitConverter.ToString(SHA512.Create().ComputeHash(ASCIIEncoding.ASCII.GetBytes(shafingerPrint)));
                    shafingerPrint = shafingerPrint.Replace('-', ':');

                    if (!onVerifyFingerPrint(publicMessage.Modulus, md5fingerPrint, shafingerPrint))
                    {
                        base.Client.Dispose();
                        return;
                    }
                }
                
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                byte[] NewKey = new byte[32];
                rng.GetBytes(NewKey);

                byte[] EncryptedNewKey = RsaCrypto.Encrypt(NewKey, true);

                base.SendMessage(new KeyReplyMessage(EncryptedNewKey), new NullHeader());
                base.Client.Connection.ApplyNewKey(NewKey, base.Client.Connection.NetworkKeySalt);
            }
            else if (base.Client.IsServerSided && replyKeyMessage != null)
            {
                byte[] NewKey = RsaCrypto.Decrypt(replyKeyMessage.NewKey, true);
                base.Client.Connection.ApplyNewKey(NewKey, base.Client.Connection.NetworkKeySalt);
                base.Finish();
            }
        }

        public override void onFinish()
        {
            base.Client.MessageHandler.RemoveMessage("RSA_PUBLIC_KEY_MESSAGE");
            base.Client.MessageHandler.RemoveMessage("RSA_REPLY_KEY_MESSAGE");
        }

        [ProtoContract]
        [Attributes.Serialization(typeof(ProtobufSerialization))]
        public class PublicKeyMessage : IMessage
        {
            [ProtoMember(1)]
            public byte[] Modulus;

            [ProtoMember(2)]
            public byte[] Exponent;

            [ProtoMember(3)]
            public byte[] SignedData;

            public PublicKeyMessage(RSACryptoServiceProvider Crypto, RSAParameters RsaParams)
            {
                this.Modulus = RsaParams.Modulus;
                this.Exponent = RsaParams.Exponent;
                this.SignedData = Crypto.SignData(Modulus, new SHA512CryptoServiceProvider());
            }

            public PublicKeyMessage()
            {

            }

            public override void ProcessPayload(SSPClient client, Network.OperationalSocket OpSocket)
            {

            }
        }


        [ProtoContract]
        [Attributes.Serialization(typeof(ProtobufSerialization))]
        public class KeyReplyMessage : IMessage
        {
            [ProtoMember(1)]
            public byte[] NewKey;

            public KeyReplyMessage(byte[] NewKey)
            {
                this.NewKey = NewKey;
            }

            public KeyReplyMessage()
            {

            }

            public override void ProcessPayload(SSPClient client, Network.OperationalSocket OpSocket)
            {

            }
        }
    }
}