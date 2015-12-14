using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.Encryptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Security.Layers
{
    public class AesLayer : ILayer
    {
        private HwAes EncAES;
        private Connection connection;

        public AesLayer(Connection connection)
        {
            this.connection = connection;
            this.EncAES = new HwAes(connection, connection.NetworkKey, 256, CipherMode.CBC, PaddingMode.PKCS7);
        }

        public LayerType Type
        {
            get
            {
                return LayerType.Encryption;
            }
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {
            //this.EncAES.Key = Key;
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            OutData = EncAES.Encrypt(InData, InOffset, InLen);
            OutOffset = 0;
            OutLen = OutData.Length;
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            OutData = EncAES.Decrypt(InData, InOffset, InLen);
            OutOffset = 0;
            OutLen = OutData.Length;
        }
    }
}
