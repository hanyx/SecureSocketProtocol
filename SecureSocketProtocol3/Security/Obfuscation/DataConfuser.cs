using SecureSocketProtocol3.Network;
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

namespace SecureSocketProtocol3.Security.Obfuscation
{
    public class DataConfuser
    {
        const int BOX_SIZE = 256;
        public int DataSize { get; private set; }

        private byte[,] BOX_A;
        private byte[,] BOX_B;

        public DataConfuser(int Seed, int DataSize)
        {
            //initialize the boxes
            this.DataSize = DataSize;
            BOX_A = new byte[DataSize, BOX_SIZE];
            BOX_B = new byte[DataSize, BOX_SIZE];

            InitBoxes(Seed);
        }

        public void Obfuscate(ref byte[] HeaderData, int Offset)
        {
            for (int i = 0; i < DataSize; i++)
            {
                //convert the data to Box A
                HeaderData[Offset + i] = BOX_A[i, HeaderData[Offset + i]];
            }
        }

        public void Deobfuscate(ref byte[] HeaderData, int Offset)
        {
            for (int i = 0; i < DataSize; i++)
            {
                //convert the data to Box B
                HeaderData[Offset + i] = BOX_B[i, HeaderData[Offset + i]];
            }
        }

        private void InitBoxes(int Seed)
        {
            for (int i = 0; i < DataSize; i++)
            {
                //set random values in Box B (The output box)
                byte[] TempValues = new byte[BOX_SIZE];
                for (int x = 0; x < BOX_SIZE; x++)
                    TempValues[x] = (byte)x;
                ShuffleValues(TempValues, Seed);

                for (int j = 0; j < BOX_SIZE; j++)
                {
                    BOX_B[i, j] = TempValues[j];
                }

                //Set in Box A where the index of Box B
                for (int j = 0; j < BOX_SIZE; j++)
                {
                    for (int x = 0; x < BOX_SIZE; x++)
                    {
                        if (BOX_B[i, x] == j)
                        {
                            BOX_A[i, j] = (byte)x;
                            break;
                        }
                    }
                }
            }
        }

        private void ShuffleValues(byte[] values, int Seed)
        {
            FastRandom rnd = new FastRandom(Seed);
            for (int i = values.Length, j = 0; i > 1; i--, j++)
            {
                int pos = rnd.Next(i);
                byte tmp = values[pos];
                values[pos] = values[i - 1];
                values[i - 1] = tmp;
            }
        }
    }
}