using SecureSocketProtocol3.Security.Encryptions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

/*
    Secure Socket Protocol
    Copyright (C) 2016 AnguisCaptor

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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