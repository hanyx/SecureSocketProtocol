using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.Encryptions;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

/*
    The MIT License (MIT)

    Copyright (c) 2016 AnguisCaptor

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace SecureSocketProtocol3.Security.Layers
{
    public class TwoFishLayer : ILayer
    {
        private TwofishManaged TwoFish;
        private Connection connection;
        private ICryptoTransform encryptTransformer;
        private ICryptoTransform decryptTransformer;

        public TwoFishLayer(Connection connection)
        {
            this.connection = connection;
            this.TwoFish = new TwofishManaged();
        }

        public LayerType Type
        {
            get { return LayerType.Encryption; }
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            lock (TwoFish)
            {
                OutOffset = 0;
                OutData = encryptTransformer.TransformFinalBlock(InData, InOffset, InLen);
                OutLen = OutData.Length;
            }
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            lock (TwoFish)
            {
                OutOffset = 0;
                OutData = decryptTransformer.TransformFinalBlock(InData, InOffset, InLen);
                OutLen = OutData.Length;
            }
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {
            lock (TwoFish)
            {
                this.encryptTransformer = this.TwoFish.CreateEncryptor(KeyExtender(Key, 32), KeyExtender(Salt, 16));
                this.decryptTransformer = this.TwoFish.CreateDecryptor(KeyExtender(Key, 32), KeyExtender(Salt, 16));
            }
        }

        private byte[] KeyExtender(byte[] Input, int TargetLen)
        {
            int temp = 0xFF28423;
            for (int i = 0; i < Input.Length; i++)
                temp += Input[i];

            int oldLen = Input.Length;
            FastRandom rnd = new FastRandom(temp);
            Array.Resize(ref Input, TargetLen);
            rnd.NextBytes(Input, oldLen, TargetLen);
            return Input;
        }
    }
}