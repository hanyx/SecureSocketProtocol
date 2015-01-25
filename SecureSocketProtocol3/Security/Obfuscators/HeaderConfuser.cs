using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.Obfuscators
{
    internal class HeaderConfuser
    {
        public HeaderConfuser(int Seed)
        {
            //initialize the boxes
            InitBoxes(Seed);
        }

        public void Obfuscate(ref byte[] HeaderData, int Offset)
        {
            /*for (int i = 0; i < Connection.HEADER_SIZE; i++)
            {
                //convert the data to Box A
                HeaderData[i] = BOX_A[i, HeaderData[i]];
            }*/
        }

        public void Deobfuscate(ref byte[] HeaderData, int Offset)
        {

        }

        private void InitBoxes(int Seed)
        {
            FastRandom rnd = new FastRandom(Seed);

            for (int i = 0; i < Connection.HEADER_SIZE; i++)
            {
                byte[] TempValues = new byte[255];
                for (byte x = 0; x < 255; x++)
                    TempValues[x] = x;
                ShuffleValues(TempValues, Seed);

                for (int j = 0; j < 255; j++)
                {
                    BOX_B[i, j] = TempValues[j];
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


        private byte[,] BOX_A = new byte[Connection.HEADER_SIZE, 255];


        private byte[,] BOX_B = new byte[Connection.HEADER_SIZE, 255];
    }
}