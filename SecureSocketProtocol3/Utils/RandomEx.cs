using SecureSocketProtocol3.Encryptions;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Utils
{
    /// <summary>
    /// RandomEx is a experimental Random class
    /// </summary>
    public class RandomEx
    {
        //By using WopEx we could technically could encrypt/decrypt the random seed we get by Calling GetNext, maybe a fun idea for in the future
        private WopEx wopEx;
        private byte[] encryptCode;
        private byte[] decryptCode;
        private byte[] IntData;

        private static byte[] InitialVector = new byte[] //64Byte IV
        {
            129, 207, 129, 148, 64, 60, 173, 27, 17, 75,
            216, 254, 96, 49, 84, 97, 253, 4, 174, 234,
            204, 89, 45, 36, 255, 4, 194, 53, 223, 78,
            205, 41, 249, 171, 213, 71, 2, 188, 23, 137,
            229, 221, 77, 198, 20, 55, 189, 241, 205, 86,
            61, 43, 24, 27, 104, 84, 37, 255, 59, 209,
            188, 74, 65, 180
        };

        public RandomEx()
        {
            Random rnd = new Random();

            // test/generate the random algorithm
            while (true)
            {
                List<int> temp = new List<int>();
                IntData = BitConverter.GetBytes(rnd.Next());
                WopEx.GenerateCryptoCode(rnd.Next(), 10, ref encryptCode, ref decryptCode);
                this.wopEx = new WopEx(BitConverter.GetBytes(rnd.Next()), BitConverter.GetBytes(rnd.Next()), InitialVector, encryptCode, decryptCode, WopEncMode.ShuffleInstructions);
                bool success = true;

                for (int i = 0; i < 100; i++)
                {
                    int tmpInt = GetNext();
                    if (!temp.Contains(tmpInt))
                        temp.Add(tmpInt);
                    else
                    {
                        success = false;
                        break;
                    }
                }
                if (success)
                    break;
                temp.Clear();
            }
        }

        public int GetNext(int max)
        {
            return GetNext() & max;
        }
        public int GetNext(int min, int max)
        {
            int rnd = GetNext();

            while(rnd < min || rnd > max)
                rnd = GetNext();

            return rnd;
        }

        public int GetNext()
        {
            wopEx.Encrypt(IntData, 0, 4);
            return BitConverter.ToInt32(IntData, 0);
        }

        public uint GetUNext()
        {
            wopEx.Encrypt(IntData, 0, 4);
            return BitConverter.ToUInt32(IntData, 0);
        }
    }
}