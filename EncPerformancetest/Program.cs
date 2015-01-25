using SecureSocketProtocol3.Security.Encryptions;
using SecureSocketProtocol3.Security.Encryptions.Compiler;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncPerformancetest
{
    class Program
    {
        private static readonly byte[] TestKey = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
        private static readonly byte[] TestSalt = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
        private static readonly byte[] TestIV = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 2, 2, 2, 2, 3, 3, 3, 3 };

        static void Main(string[] args)
        {
            Test lel = new Test();
            ulong um = lel.CalculateULong(1);

            if (um == 0)
                return;

            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1 };

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(123456, 100, ref encCode, ref decCode);

            WopEx wopEx = new WopEx(TestKey, TestSalt, TestIV, encCode, decCode, SecureSocketProtocol3.WopEncMode.GenerateNewAlgorithm, 1, true);

            Random rnd = new Random(12345678);

            long TotalData = (1000 * 1000) * 100;
            long TotalDone = 0;
            byte[] DataChunk = new byte[65535];
            //rnd.NextBytes(DataChunk);

            Stopwatch SW = Stopwatch.StartNew();

            //simple AES test
            HwAes AES = new HwAes(Key, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, 256, CipherMode.CBC, PaddingMode.PKCS7);
            HwAes AES2 = new HwAes(Key, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, 256, CipherMode.CBC, PaddingMode.PKCS7);

            while (true)
            {
                byte[] enc = AES.Encrypt(DataChunk, 0, DataChunk.Length);
                TotalDone += DataChunk.Length;

                if (SW.ElapsedMilliseconds >= 1000)
                {
                    double speed = Math.Round((TotalDone / 1000D) / 1000D, 2);
                    Console.WriteLine("Speed: " + speed + "MBps (" + Math.Round((((double)speed * 8F) / 1000), 2) + " Gbps)");
                    TotalDone = 0;
                    SW = Stopwatch.StartNew();
                }
            }
            
            
            Stopwatch TotalTimeSW = Stopwatch.StartNew();
            double TempSpeed = 0;
            
            while (TotalDone < TotalData)
            {
                wopEx.Encrypt(DataChunk, 0, DataChunk.Length);
                //wopEx.Decrypt(DataChunk, 0, DataChunk.Length);
                TotalDone += DataChunk.Length;
                TempSpeed += DataChunk.Length;

                if (SW.ElapsedMilliseconds >= 1000)
                {
                    double speed = Math.Round((TempSpeed / 1000D) / 1000D, 2);
                    Console.WriteLine("Speed: " + speed + "MBps");
                    TempSpeed = 0;
                    SW = Stopwatch.StartNew();
                }
            }
            SW.Stop();
            TotalTimeSW.Stop();

            if (TempSpeed > 0)
            {
                double speeds = Math.Round((TempSpeed / 1000D) / 1000D, 2);
                Console.WriteLine("Speed: " + speeds + "MBps");
            }

            Console.WriteLine("Done encrypting 100MB in " + TotalTimeSW.Elapsed.Seconds + " second(s)");
            Console.ReadLine();
        }
    }

    public class Test : IAlgorithm
    {
        public void Testy(ulong asd)
        {
            asd ^= (ulong)507843278342L;
        }

        public byte CalculateByte(byte Value)
        {
            Value += 50;
            Value += 100;
            return Value;
        }

        public ulong CalculateULong(ulong value)
        {
            //value += (ulong)8885562610731955687;

            value = ((0x00000000000000FF) & (value >> 56) |
                    (0x000000000000FF00) & (value >> 40) |
                    (0x0000000000FF0000) & (value >> 24) |
                    (0x00000000FF000000) & (value >> 8) |
                    (0x000000FF00000000) & (value << 8) |
                    (0x0000FF0000000000) & (value << 24) |
                    (0x00FF000000000000) & (value << 40) |
                    (0xFF00000000000000) & (value << 56));

            return value;
            //value -= 0xFF00000000000000L;
            //Value -= 120;
            //Value += 150;
            //return value;
        }
    }
}
