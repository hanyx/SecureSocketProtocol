using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.Encryptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Security.Layers
{
    public class AesCtrLayer : ILayer
    {
        public LayerType Type
        {
            get
            {
                return LayerType.Encryption;
            }
        }

        Aes128CounterMode AesCtr_enc;
        Aes128CounterMode AesCtr_dec;

        ICryptoTransform AesCtrCrpyotEnc;
        ICryptoTransform AesCtrCrpyotDec;

        public byte[] Key1 = null;
        public byte[] Key2 = null;
        public byte[] Counter1 = null;
        public byte[] Counter2 = null;

        public AesCtrLayer(Connection connection)
        {
            ApplyKey(connection.NetworkKey, connection.NetworkKeySalt);
        }
        public AesCtrLayer(byte[] Key, byte[] Counter)
        {
            ApplyKey(Key, Counter);
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {

            Counter1 = new byte[16];
            Counter2 = new byte[16];
            Array.Copy(Salt, 0, Counter1, 0, Counter1.Length);
            Array.Copy(Salt, 0, Counter2, 0, Counter2.Length);

            Key1 = new byte[16];
            Key2 = new byte[16];
            Array.Copy(Key, 0, Key1, 0, Key1.Length);
            Array.Copy(Key, 0, Key2, 0, Key2.Length);

            this.AesCtr_enc = new Aes128CounterMode(Counter1);
            this.AesCtr_dec = new Aes128CounterMode(Counter2);
            this.AesCtrCrpyotEnc = this.AesCtr_enc.CreateEncryptor(Key1, null);
            this.AesCtrCrpyotDec = this.AesCtr_dec.CreateDecryptor(Key2, null);
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            OutData = new byte[InLen];
            OutLen = AesCtrCrpyotEnc.TransformBlock(InData, InOffset, InLen, OutData, OutOffset);
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            OutData = new byte[InLen];
            OutLen = AesCtrCrpyotDec.TransformBlock(InData, InOffset, InLen, OutData, OutOffset);
        }
    }
}
