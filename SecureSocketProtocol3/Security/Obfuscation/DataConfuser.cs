using SecureSocketProtocol3.Network;
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