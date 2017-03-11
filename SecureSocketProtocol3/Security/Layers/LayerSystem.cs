using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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
    public class LayerSystem
    {
        private List<ILayer> _layers;

        public ILayer[] Layers
        {
            get { return _layers.ToArray(); }
        }

        public SSPClient Client { get; private set; }

        public LayerSystem(SSPClient Client)
        {
            this._layers = new List<ILayer>();
            this.Client = Client;
        }

        public void AddLayer(ILayer Layer)
        {
            lock (_layers)
            {
                //apply initial key
                Layer.ApplyKey(Client.Connection.NetworkKey, Client.Connection.NetworkKeySalt);
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
                OutData = InData;
                OutOffset = InOffset;
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

        internal void ApplyKeyToLayers(byte[] Key, byte[] Salt)
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