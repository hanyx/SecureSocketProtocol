using SecureSocketProtocol3;
using SecureSocketProtocol3.Security.Encryptions;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace EncryptionTests
{
    class Program
    {
        private static WopEx wop_enc;
        private static WopEx wop_dec;
        static void Main(string[] args)
        {
            RSA_Test();

            while(true)
            {
                byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, };
                byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, };
                byte[] IV = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, };

                byte[] EncryptCode = new byte[0];
                byte[] DecryptCode = new byte[0];
                WopEx.GenerateCryptoCode(12345678, 20, ref EncryptCode, ref DecryptCode);
                wop_enc = new WopEx(Key, Salt, IV, EncryptCode, DecryptCode, WopEncMode.GenerateNewAlgorithm, 1, true);
                wop_dec = new WopEx(Key, Salt, IV, EncryptCode, DecryptCode, WopEncMode.GenerateNewAlgorithm, 1, true);

                //if (File.Exists("./temp.txt"))
                //    File.Delete("./temp.txt");

                Log("WopEx Algorithm with Shuffle algorithm enabled");
                Log("Key:  " + BitConverter.ToString(Key));
                Log("Salt: " + BitConverter.ToString(Salt));
                Log();

                Log("Encryption Algorithm:");
                ShowAlgorithm(wop_enc);

                byte[] Data = new byte[] { 1, 3, 3, 7 };

                //while(true)
                {
                    EncDec(Data);
                }

            }
            Process.GetCurrentProcess().WaitForExit();
        }

        private static void ShowAlgorithm(WopEx wop)
        {
            /*Log("Instructions: " + wop..EncInstructions.Length);

            foreach (WopEx.InstructionInfo inf in wop.EncInstructions)
            {
                if (inf.Inst != WopEx.Instruction.ForLoop_PlusMinus)
                {
                    Log("Instruction:" + inf.Inst + ", value: " + inf.Value);
                }
                else
                {
                    Log("\r\nInstruction:" + inf.Inst + ":");
                    Log("for(int i = 0; i < " + (inf.Value3 >> 1) + "; i++)");
                    Log("{");
                    Log("\tvalue -= " + inf.Value + ";");
                    Log("\tvalue += " + inf.Value2 + ";");
                    Log("}");
                    Log();
                }
            }*/
        }

        private static void Log()
        {
            Log("\r\n");
        }
        private static void Log(string message)
        {
            using (StreamWriter sw = File.AppendText("./temp.txt"))
            {
                sw.WriteLine(message);
                sw.Flush();
                Console.WriteLine(message);
            }
        }

        private static void EncDec(byte[] Data)
        {
            //Log("=============================== Encrypting data ===============================");
            //Log("Original Data:" + BitConverter.ToString(Data).Replace("-", " "));
            wop_enc.Encrypt(Data, 0, Data.Length);
            //Log("Encrypted Data:" + BitConverter.ToString(Data).Replace("-", " "));

            //Log("\r\n\r\n====================New Encryption Algorithm: ====================");
            ShowAlgorithm(wop_enc);

            wop_dec.Decrypt(Data, 0, Data.Length);
            //Log("Decrypted data: " + BitConverter.ToString(Data).Replace("-", " "));
        }

        private static void RSA_Test()
        {
            //RSAEncryption GenPrivateKeyc = new RSAEncryption(4096, true);
            //GenPrivateKeyc.GeneratePrivateKey();
            //string PrivateKey = GenPrivateKeyc.PrivateKey;

            int BitSize = 4096;
            string PreGenPrivateKey = @"<RSAKeyValue>
                                            <Modulus>1ClYJTeXDkbppKjvJqC3xf+E4P4eVa4lwvFmdGTsqDdJoT+RMvLg/WkrWsCEASmxaj3ohlg1kBhSv2ZXuZlH90Roba5EWOxD1EQUDjk0e711ga0YVwZF5UUo9yx+Lo1QR3ErmeNMOkJDa0IZVnmuILgdaTFBdBm2ZYdJVnpeB+BIycNT0vAoqtwdDZXySjAzfl6nL6WsNw/XqJMIDuFcIt8hv6vghFtpiQXeWEsuZq3DQPlCu0oJDYuoAaRU5KxOIakbTzpTS11eBx+w1PDgd+VCAEVbx71sqjSFsAOEvmm4A0lRBRnQuJOdoGLNFoSePDGP9J88KfIfosMtAqFDUX2/8EsAc6B3QnpQ0un5vC2Au0xUDY0fwsKtN9yvFQPw10eRXEV+Smz4pBH+4gOEKi0RxNt3chKa0qqGG9I/CqL1/PPEtvN31Bjxc4H2vAyW3XMRNs7o9pktimaRNpwZ6sbBDi2eNY6Ty5ff7jHv0uy9DRQsreTewhXvZK6M8OcBUxLp1tkzi9zTBKTPTMXAuUF1oWDJktWDBuGnxbZcTfTvJ0X3zS8/mXdsUHsgV5vcGeT+2hZLQnskrwlbxt4QjEHSl0hgWM9i5Yhd+ltlg/9URvZdnkh5pKoShJR4OWNSBsI3kwRzwPHAKag8J4TSFIgZXCkSvtTlsM6v44f8pNU=</Modulus>
                                            <Exponent>AQAB</Exponent>
                                            <P>3cBHXk4SpnPWskCpGfJbW5u5XO3q1srmsW9XCDwo4HWezMaIjznjcwd46W50nUAkfS6zt91Ez7xPzWg0+kTrLwJEnAwLb5rYk7aGk29G8Vz0DW6rBnzT8hIxgdAnRUk/Htxkee1k8aHdL5kDUkfBDX1sRxi20A8bNHG039oq0joxkQKO8nrctIxHLiTtPXUH1R3AZ4+35keONp4iRBvKudPlZFOGHw4JmtW/mm6opAHOMZJyMpz6LFbQuQ6FAb7YkP63e0qELgP5PgnFgz/k2vA5gqjCfLdHNqh4o9iTuEDh8JPY4ADu3JkaJXdp3NPn2vsZHW3IJQON4WnjfFB3mQ==</P>
                                            <Q>9O3oLQiJXD3O9aQnyUpI4MQjJ2JacXCbNmcS8Kv+U1eYpQqQK1PwJCl2jJ8KgP7Hy8H3kuUxMDFv1fuWO1UFC4fzrODx5W6Vo/ZUhud0l8q8OfQKq4YOmpHR/eFAj9Bo3bGNXnjBWCV0RmxA0cAQ/y/bAdBTOQntBQUNLqfstTu6fAMor6fzYpzic1olUlOQf9wCOHNE/JSgjMgaXdpYLxLsCSexN/ut8T8fxBSX3NeSUlLbj2CWtzEGsKwP7rwIfnZ9UUKdBCaGAj2UIi5wO2TBnEb0EhjRcOa15YThZTp+4U6LQNVJC9nK26yhBrWH2ZEft5a0nPgJLIabT90snQ==</Q>
                                            <DP>yVS/92FPEY1uylxmq8YdKClUvIjOhMGnfkWmcTWdr11bFnTSm6dlWJTaNKYyfms0NevnA/KDfVBt7ALGxss39HBMtplA8M1YAZTgzo9ji9RnSKLH6JYBIHFgPYotfXypMG3NU94znibl2UdFerjnEEZlvo8zu+dbPdxW6j78Te7D/fKisojWRZ5vKfgg5YGR4O6oN96Giy9AcVpVphzNjLZUOSiURzHJiqiy05XQy0dQXDWoNUfM4+DWlI4YOKN7oPmCwQ/Avr6g1rCsgSPLtvQQYw6xteX5ZCjFj40dYVaXTIQPjiGKvQLMeGPY28QRaAI+pTd9Vg3KDXTEM6QjUQ==</DP>
                                            <DQ>ENQz6rw2a+8XREuGLE99WGxBmhgo7Lh3AbLtWzoGHIXdSCHErCV1T5bFvX3EA/79jWODdkVnLs+GxqYluWfrE9LAjHVcSY5im8R2JFrM6Q0WB8lb3lM0t6wjSJVskTUZr3neo8oaRss0BQ61GXRf9pi8LJC61yV2cqzZLgZ9viofcxvodMFOeM0cxh5AiDqTqCVexbAt4kj4CxRIs4AoJPvg2fQvOhCB8ByNOzTLBnKNbDijO2PAl0+4DPWVlqq2zrGnhKjWDw3ykT7X6c1VCs+ueeVqKcAoy+AeSWnq7sCpLSPvb4H4JedOB/ABlGturSVKj5u8RzjHsJaDH2asBQ==</DQ>
                                            <InverseQ>YTR07LDfg26rZt6gaVlxYioX/UhbjoIPnH5Gd1ZcaGBfnkzaXatHv6YDA0wuj2VmAelmdTMD21H2TgHvvRRnpsVix/+uphV71QCKPBooJke/Dba2YxRYz5UYWid/VDvtFddzw3NdQF8mzqhr/FpdrZWeLiuDHlZLmQxqNWRlpFX1w1CBMZBuv8Z2cLf//sr/rZ3bY9F6EXqLoMIOnp+Gv069pfp7xpm5Ymcz3ixmCXY0BiwHxfbw2YAQus1Q3s+GSqtVU6IYFe6VbwdcRR45WdFEMF2I6mboehN2pTAUyEkvYIYra/pfjkXrTKPTvyucR1BmObKYqg9jKIXLKH3IRA==</InverseQ>
                                            <D>Ig0isxJ5gZabEEz22T3JUROCKbRPfRPuxpuFBKBgJV1+SU2RCdrWhoWXKkEkzqT47yLRi6JjsmVc/pA3+zdhSAvoMNZb7OO6vTpR97hxtnyBfBcihXEhzbrsaMNw2xreLCE7TL8g8GbLOE9LDsiHzIOQYN5BcZdg4Wm1uRX5uoziUdOyQ/Q8qrOaTCBpW0PiN+GMNscB3XKC+/DhRbYg2g3y9jbpWYTsaswQ1B347AzufiKjdbjbvBtSkzTjVTJcdeWU1wH29W0eVslc0ch5VnTqw21eXjAGXUkBve7Kot8H5CsjwExU5hL3JRNGdFtDpEiWIL5f4yGTt0VZF4d3bLV5q3R3l34ghdt171tShSGz013J0Z5Q/iHBgRkSR//0f8ZITe7iSkhkfZXbx7Ihi13ufBJwIdcDhT7LYKHLk/H3fgCnkAigEmT14/oZwYtW0CqnHtzbBpO+jPLIMAFbhty6GE2LKlQx91YwqMODnYRYs7e8evOeiAadLAjAxQOjNZ1J8EKfwmtmqBqfiUA5O1uJRAavuMhRw/UTMqOeBEGxosmUsV4aw9BIYASmJ9uzc7pkZdPwBlVdnHPn5MILmAcE2vYhv9bRgwUF8LRT4GkP9IW2g48WabzLhIdSu/azjT2GBnkMwz5FcwPYiFvQc3fquqVWhn9PqGN5tHq6LhE=</D>
                                        </RSAKeyValue>";

            RSAEncryption A_Rsa = new RSAEncryption(BitSize, "", PreGenPrivateKey, true);

            //When generating, only the modulus and Exponent should be made public, nothing else
            string PublicKeyFromA = A_Rsa.GeneratePublicKey();

            string TestData = "Helllo, This is A, let's hope this message arrived well";
            byte[] EncryptedData = A_Rsa.Encrypt(ASCIIEncoding.ASCII.GetBytes(TestData), 0, TestData.Length);
            byte[] SignedData = A_Rsa.SignData(ASCIIEncoding.ASCII.GetBytes(TestData));

            RSAEncryption B_Rsa = new RSAEncryption(BitSize, A_Rsa.PublicParameters.Value.Modulus, A_Rsa.PublicParameters.Value.Exponent, true);

            byte[] DecryptedData = B_Rsa.Decrypt(EncryptedData, 0, EncryptedData.Length);
        }
    }
}