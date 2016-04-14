using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Utils
{
    //Thanks to: http://stackoverflow.com/questions/4892588/rngcryptoserviceprovider-random-number-review/21368331#21368331
    //Modified it to my needs + bug fixes
    public class SecureRandom
    {
        #region Constants
        private const int INT_SIZE = 4;
        private const int INT64_SIZE = 8;
        #endregion

        #region Fields
        private RandomNumberGenerator _Random;
        #endregion

        #region Constructor
        public SecureRandom()
        {
            _Random = new RNGCryptoServiceProvider();
        }
        #endregion

        #region Random int
        /// <summary>
        /// Get the next random integer
        /// </summary>
        /// <returns>Random [int]</returns>
        public int Next()
        {
            byte[] data = new byte[INT_SIZE];
            int[] result = new int[1];

            do
            {
                _Random.GetBytes(data);
                Buffer.BlockCopy(data, 0, result, 0, INT_SIZE);
            } while (result[0] < 0);

            return result[0];
        }

        /// <summary>
        /// Get the next nonnegative random integer to a maximum value
        /// </summary>
        /// <param name="MaxValue">Maximum value</param>
        /// <returns>Random [int]</returns>
        public int Next(int MaxValue)
        {
            return Math.Abs(Next()) % MaxValue;
        }

        /// <summary>
        /// Get the next nonnegative random integer to a maximum value
        /// </summary>
        /// <param name="MaxValue">Maximum value</param>
        /// <returns>Random [int]</returns>
        public int Next(int MinValue, int MaxValue)
        {
            int result = 0;

            if (MinValue == MaxValue)
                return MinValue;

            do
            {
                result = Math.Abs(Next()) % MaxValue;
            } while (result < MinValue);

            return result;
        }
        #endregion

        #region Random Uint
        /// <summary>
        /// Get the next random unsigned integer
        /// </summary>
        /// <returns>Random [Uint]</returns>
        public uint NextUInt()
        {
            byte[] data = new byte[INT_SIZE];
            int[] result = new int[1];

            do
            {
                _Random.GetBytes(data);
                Buffer.BlockCopy(data, 0, result, 0, INT_SIZE);
            } while (result[0] <= 0);

            return (uint)result[0];
        }

        /// <summary>
        /// Get the next random unsigned integer to a maximum value
        /// </summary>
        /// <param name="MaxValue">Maximum value</param>
        /// <returns>Random [Uint]</returns>
        public uint NextUInt(uint MaxValue)
        {
            return NextUInt() % MaxValue;
        }

        /// <summary>
        /// Get the next random unsigned integer to a maximum value
        /// </summary>
        /// <param name="MaxValue">Maximum value</param>
        /// <returns>Random [Uint]</returns>
        public uint NextUInt(uint MinValue, uint MaxValue)
        {
            uint result = 0;

            if (MinValue == MaxValue)
                return MinValue;

            do
            {
                result = NextUInt() % MaxValue;
            } while (result < MinValue);

            return result;
        }
        #endregion

        #region Random long
        /// <summary>
        /// Get the next random integer
        /// </summary>
        /// <returns>Random [int]</returns>
        public long NextLong()
        {
            byte[] data = new byte[INT64_SIZE];
            long[] result = new long[1];

            _Random.GetBytes(data);
            Buffer.BlockCopy(data, 0, result, 0, INT64_SIZE);

            return result[0];
        }

        /// <summary>
        /// Get the next random unsigned long to a maximum value
        /// </summary>
        /// <param name="MaxValue">Maximum value</param>
        /// <returns>Random [ulong]</returns>
        public long NextLong(long MaxValue)
        {
            return Math.Abs(NextLong()) % MaxValue;
        }

        /// <summary>
        /// Get the next random unsigned long to a maximum value
        /// </summary>
        /// <param name="MaxValue">Maximum value</param>
        /// <returns>Random [ulong]</returns>
        public long NextLong(long MinValue, long MaxValue)
        {
            long result = 0;

            if (MinValue == MaxValue)
                return MinValue;

            do
            {
                result = Math.Abs(NextLong()) % MaxValue;
            } while (result < MinValue);

            return result;
        }
        #endregion

        #region Random Uint
        /// <summary>
        /// Get the next random unsigned long
        /// </summary>
        /// <returns>Random [ulong]</returns>
        public ulong NextULong()
        {
            byte[] data = new byte[INT64_SIZE];
            ulong[] result = new ulong[1];

            do
            {
                _Random.GetBytes(data);
                Buffer.BlockCopy(data, 0, result, 0, INT64_SIZE);
            } while (result[0] < 0);

            return (ulong)result[0];
        }

        /// <summary>
        /// Get the next random unsigned long to a maximum value
        /// </summary>
        /// <param name="MaxValue">Maximum value</param>
        /// <returns>Random [ulong]</returns>
        public ulong NextULong(ulong MaxValue)
        {
            return NextULong() % MaxValue;
        }

        /// <summary>
        /// Get the next random unsigned long to a maximum value
        /// </summary>
        /// <param name="MaxValue">Maximum value</param>
        /// <returns>Random [ulong]</returns>
        public ulong NextULong(ulong MinValue, ulong MaxValue)
        {
            ulong result = 0;

            if (MinValue == MaxValue)
                return MinValue;

            do
            {
                result = NextULong();
            } while (result < MinValue);

            return result % MaxValue;
        }
        #endregion

        #region Random Bytes
        /// <summary>
        /// Get random bytes
        /// </summary>
        /// <param name="data">Random [byte array]</param>
        public byte[] NextBytes(long Size)
        {
            byte[] data = new byte[Size];
            _Random.GetBytes(data);
            return data;
        }
        #endregion
    }
}
