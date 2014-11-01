using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureSocketProtocol3.Encryptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SSPTests
{
    [TestClass()]
    public class WopExTests
    {
        [TestMethod()]
        public void Test_WopEx_NoSuffle()
        {
            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1  };

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(123456, 15, ref encCode, ref decCode);

            WopEx wopEx = new WopEx(Key, Salt, encCode, decCode, SecureSocketProtocol3.WopEncMode.Simple);

            Random rnd = new Random(DateTime.Now.Millisecond);

            for (int j = 1; j < 1024; j++) //test 1024 bytes
            {
                for(int k = 0; k < 100; k++) //test the encryption / decryption 100x
                {
                    //test the byte a 100x
                    byte[] TestData = new byte[j];
                    byte[] TestOrgData = new byte[j];
                    rnd.NextBytes(TestData);
                    Array.Copy(TestData, TestOrgData, TestOrgData.Length);

                    wopEx.Encrypt(TestOrgData, 0, TestData.Length);
                    wopEx.Decrypt(TestOrgData, 0, TestData.Length);

                    Assert.IsTrue(TestOrgData.Length == TestData.Length, "Size did not match after decryption");

                    for (int x = 0; x < TestData.Length; x++)
                    {
                        Assert.IsTrue(TestData[x] == TestOrgData[x], "Decryption failed");
                    }
                }
            }
        }


        [TestMethod()]
        public void Test_WopEx_GenerateNewAlgorithm()
        {
            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1 };

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(123456, 15, ref encCode, ref decCode);

            WopEx wopEx = new WopEx(Key, Salt, encCode, decCode, SecureSocketProtocol3.WopEncMode.GenerateNewAlgorithm);

            Random rnd = new Random(12345678);

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

                    if(TestOrgData.Length != TestData.Length)
                        throw new Exception("Size did not match after decryption");

                    for (int x = 0; x < TestData.Length; x++)
                    {
                        if(TestData[x] != TestOrgData[x])
                            throw new Exception("Decryption failed, j=" + j + ", k=" + k);
                    }
                }
            }
        }


        [TestMethod()]
        public void Test_WopEx_ShuffleInstructions()
        {
            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1 };

            byte[] encCode = new byte[0];
            byte[] decCode = new byte[0];
            WopEx.GenerateCryptoCode(123456, 15, ref encCode, ref decCode);

            WopEx wopEx = new WopEx(Key, Salt, encCode, decCode, SecureSocketProtocol3.WopEncMode.ShuffleInstructions);

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
        }
    }
}