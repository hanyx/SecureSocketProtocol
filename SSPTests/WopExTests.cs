using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureSocketProtocol3.Security.Encryptions;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace SSPTests
{
    [TestClass()]
    public class WopExTests
    {
        private static readonly byte[] TestKey = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
        private static readonly byte[] TestSalt  = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
        private static readonly byte[] TestIV = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 2, 2, 2, 2, 3, 3, 3, 3 };

        [TestMethod()]
        public void Test_WopEx_Simple()
        {
            Random rnd = new Random(DateTime.Now.Millisecond);

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(123456, 15, ref encCode, ref decCode);

            WopEx wopEx = new WopEx(TestKey, TestSalt, rnd.Next(), encCode, decCode, SecureSocketProtocol3.WopEncMode.Simple, 1, false);


            for (int j = 1; j < 1024; j++) //test 1024 bytes
            {
                for(int k = 0; k < 100; k++) //test the encryption / decryption 100x
                {
                    //test the byte a 100x
                    byte[] TestData = new byte[j];
                    byte[] TestOrgData = new byte[j];
                    rnd.NextBytes(TestData);
                    Array.Copy(TestData, TestOrgData, TestOrgData.Length);

                    using (MemoryStream encMS = new MemoryStream())
                    using (MemoryStream decMS = new MemoryStream())
                    {
                        wopEx.Encrypt(TestOrgData, 0, TestData.Length, encMS);
                        wopEx.Decrypt(encMS.ToArray(), 0, (int)encMS.Length, decMS);

                        byte[] DecryptedData = decMS.ToArray();

                        Assert.IsTrue(TestOrgData.Length == DecryptedData.Length, "Size did not match after decryption");


                        for (int x = 0; x < TestData.Length; x++)
                        {
                            Assert.IsTrue(TestData[x] == DecryptedData[x], "Decryption failed");
                        }
                    }
                }
            }
        }

        [TestMethod()]
        public void Test_WopEx_GenerateNewAlgorithm()
        {
            Random rnd = new Random(12345678);
            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1 };

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(123456, 15, ref encCode, ref decCode);

            WopEx wopEx = new WopEx(TestKey, TestSalt, rnd.Next(), encCode, decCode, SecureSocketProtocol3.WopEncMode.GenerateNewAlgorithm, 1, false);
            

            for (int j = 1; j < 1024; j++) //test 1024 bytes
            {
                for (int k = 0; k < 100; k++) //test the encryption / decryption 100x
                {
                    //test the byte a 100x
                    byte[] TestData = new byte[j];
                    byte[] TestOrgData = new byte[j];
                    rnd.NextBytes(TestData);
                    Array.Copy(TestData, TestOrgData, TestOrgData.Length);

                    using (MemoryStream encMS = new MemoryStream())
                    using (MemoryStream decMS = new MemoryStream())
                    {
                        wopEx.Encrypt(TestOrgData, 0, TestOrgData.Length, encMS);
                        wopEx.Decrypt(encMS.ToArray(), 0, (int)encMS.Length, decMS);

                        byte[] DecryptedData = decMS.ToArray();

                        if (TestOrgData.Length != DecryptedData.Length)
                            throw new Exception("Size did not match after decryption");

                        for (int x = 0; x < TestData.Length; x++)
                        {
                            if (DecryptedData[x] != TestOrgData[x])
                                throw new Exception("Decryption failed, j=" + j + ", k=" + k);
                        }
                    }
                }
            }
        }

        /*[TestMethod()]
        public void Test_WopEx_GenerateNewAlgorithm_100MB_Total_65K_Chunk()
        {
            Random rnd = new Random(12345678);
            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1 };

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(123456, 15, ref encCode, ref decCode);

            WopEx wopEx = new WopEx(TestKey, TestSalt, rnd.Next(), encCode, decCode, SecureSocketProtocol3.WopEncMode.Simple, 1, false);
            
            long TotalData = (1000 * 1000) * 100;
            long TotalDone = 0;
            byte[] DataChunk = new byte[65535];
            rnd.NextBytes(DataChunk);

            Stopwatch SW = Stopwatch.StartNew();
            List<double> SpeedPerSec = new List<double>();
            double TempSpeed = 0;

            while (TotalDone < TotalData)
            {
                //wopEx.Encrypt(DataChunk, 0, DataChunk.Length);
                //wopEx.Decrypt(DataChunk, 0, DataChunk.Length);
                TotalDone += DataChunk.Length;
                TempSpeed += DataChunk.Length;

                if (SW.ElapsedMilliseconds >= 1000)
                {
                    SpeedPerSec.Add(Math.Round((TempSpeed / 1000D) / 1000D, 2));
                    TempSpeed = 0;
                    SW = Stopwatch.StartNew();
                }
            }
            SW.Stop();
        }

        [TestMethod()]
        public void Test_WopEx_ShuffleInstructions()
        {
            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1 };

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(123456, 15, ref encCode, ref decCode);

            WopEx wopEx = new WopEx(TestKey, TestSalt, TestIV, encCode, decCode, SecureSocketProtocol3.WopEncMode.ShuffleInstructions, 1, false);

            Random rnd = new Random(DateTime.Now.Millisecond);

            for (int j = 1; j < 1024; j++) //test 1024 bytes
            {
                for (int k = 0; k < 100; k++) //test the encryption / decryption 100x
                {
                    //test the byte a 100x
                    byte[] TestData = new byte[j];
                    byte[] TestOrgData = new byte[j];
                    rnd.NextBytes(TestData);
                    Array.Copy(TestData, TestOrgData, TestOrgData.Length);

                    wopEx.Encrypt(TestData, 0, TestData.Length);
                    wopEx.Decrypt(TestData, 0, TestData.Length);

                    Assert.IsTrue(TestOrgData.Length == TestData.Length, "Size did not match after decryption");

                    for (int x = 0; x < TestData.Length; x++)
                    {
                        Assert.IsTrue(TestData[x] == TestOrgData[x], "Decryption failed");
                    }
                }
            }
        }*/
    }
}