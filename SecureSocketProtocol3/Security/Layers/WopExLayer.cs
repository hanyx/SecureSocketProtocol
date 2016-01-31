using SecureSocketProtocol3.Security.Encryptions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    public class WopExLayer : ILayer
    {
        public LayerType Type
        {
            get { return LayerType.Encryption; }
        }

        private WopEx wopEx;
        private int privateSeed;
        private int instructionCount;
        private uint cipherRounds;
        private bool useDynamicCompiler;

        public WopExLayer(int InstructionCount, uint CipherRounds, bool UseDynamicCompiler, SSPClient Client)
        {
            this.privateSeed = Client.Connection.PrivateSeed;
            this.instructionCount = InstructionCount;
            this.cipherRounds = CipherRounds;
            this.useDynamicCompiler = UseDynamicCompiler;

            byte[] Salt = new byte[Client.Connection.NetworkKey.Length];
            Array.Copy(Client.Connection.NetworkKey, Salt, Salt.Length);

            for(int i = 0; i < Salt.Length; i++)
                Salt[i] += (byte)Client.Connection.PrivateSeed;

            byte[] EncCode = new byte[0];
            byte[] DecCode = new byte[0];
            WopEx.GenerateCryptoCode(Client.Connection.PrivateSeed, InstructionCount, ref EncCode, ref DecCode);
            wopEx = new WopEx(Client.Connection.NetworkKey, Salt, Client.Connection.PrivateSeed, EncCode, DecCode, WopEncMode.ShuffleInstructions, CipherRounds, UseDynamicCompiler);
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                wopEx.Encrypt(InData, InOffset, InLen, stream);
                OutData = stream.GetBuffer();
                OutOffset = 0;
                OutLen = (int)stream.Length;
            }
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                wopEx.Decrypt(InData, InOffset, InLen, stream);
                OutData = stream.GetBuffer();
                OutOffset = 0;
                OutLen = (int)stream.Length;
            }
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {
            int newPrivSeed = BitConverter.ToInt32(Key, 0) + BitConverter.ToInt32(Salt, 0) + privateSeed;

            byte[] EncCode = new byte[0];
            byte[] DecCode = new byte[0];
            WopEx.GenerateCryptoCode(newPrivSeed, instructionCount, ref EncCode, ref DecCode);
            wopEx = new WopEx(Key, Salt, newPrivSeed, EncCode, DecCode, WopEncMode.ShuffleInstructions, cipherRounds, useDynamicCompiler);
        }
    }
}