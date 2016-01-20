using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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
    public class LayerSystem
    {
        private List<ILayer> _layers;

        public ILayer[] Layers
        {
            get { return _layers.ToArray(); }
        }

        public LayerSystem()
        {
            this._layers = new List<ILayer>();
        }

        public void AddLayer(ILayer Layer)
        {
            lock (_layers)
            {
                this._layers.Add(Layer);
            }
        }

        internal void ApplyLayers(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            foreach (ILayer Layer in _layers.Where(o => o.Type == LayerType.Compression))
            {
                Layer.ApplyLayer(InData, InOffset, InLen, ref OutData, ref OutOffset, ref OutLen);
                InData = OutData;
                InOffset = OutOffset;
                InLen = OutLen;
            }

            foreach (ILayer Layer in _layers.Where(o => o.Type == LayerType.Encryption))
            {
                Layer.ApplyLayer(InData, InOffset, InLen, ref OutData, ref OutOffset, ref OutLen);
                InData = OutData;
                InOffset = OutOffset;
                InLen = OutLen;
            }

            if (_layers.Count == 0)
            {
                OutData = new byte[InLen];
                Array.Copy(InData, InOffset, OutData, OutOffset, InLen);
                OutOffset = 0;
                OutLen = InLen;
            }
        }

        internal void RemoveLayers(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            foreach (ILayer Layer in _layers.Where(o => o.Type == LayerType.Encryption).Reverse())
            {
                Layer.RemoveLayer(InData, InOffset, InLen, ref OutData, ref OutOffset, ref OutLen);
                InData = OutData;
                InOffset = OutOffset;
                InLen = OutLen;
            }

            foreach (ILayer Layer in _layers.Where(o => o.Type == LayerType.Compression).Reverse())
            {
                Layer.RemoveLayer(InData, InOffset, InLen, ref OutData, ref OutOffset, ref OutLen);
                InData = OutData;
                InOffset = OutOffset;
                InLen = OutLen;
            }

            if (_layers.Count == 0)
            {
                OutData = new byte[InLen];
                Array.Copy(InData, InOffset, OutData, OutOffset, InLen);
                OutOffset = 0;
                OutLen = InLen;
            }
        }

        internal void ApplyKeyToLayers(SSPClient Client, byte[] Key, byte[] Salt)
        {
            foreach (ILayer Layer in _layers.Where(o => o.Type == LayerType.Encryption))
            {
                Layer.ApplyKey(Key, Salt);
            }
        }

        /// <summary>
        /// Test the layer with a few simple tests to see if it's stable for normal use, if exceptions do occur, fix them
        /// </summary>
        /// <param name="Layer"></param>
        public void TestLayer(ILayer Layer, int Iterations)
        {
            byte[] OutData = new byte[0];
            int OutOffset = 0;
            int OutLength = 0;

            Layer.ApplyLayer(null, 0, 0, ref OutData, ref OutOffset, ref OutLength);

            FastRandom rand = new FastRandom();

            //in-bound array check with offset
            for (int i = 0; i < Iterations; i++)
            {
                byte[] Input = new byte[rand.Next(0, 2500000)];
                int Offset = rand.Next(0, Input.Length);
                int InLength = Input.Length - Offset;
                rand.NextBytes(Input);
                Layer.ApplyLayer(Input, Offset, InLength, ref OutData, ref OutOffset, ref OutLength);

                byte[] OutDecryptedData = new byte[0];
                int OutDecryptedOffset = 0;
                int OutDecryptedLength = 0;
                Layer.RemoveLayer(OutData, OutOffset, OutLength, ref OutDecryptedData, ref OutDecryptedOffset, ref OutDecryptedLength);

                if (OutDecryptedLength != InLength)
                {
                    throw new Exception("Applied Layer & Removed Layer size missmatch");
                }

                for (int j = 0; j < InLength; j++)
                {
                    if (Input[j + Offset] != OutDecryptedData[j + OutDecryptedOffset])
                    {
                        throw new Exception("Input & Removed Layer output missmatch");
                    }
                }
            }
        }
    }
}