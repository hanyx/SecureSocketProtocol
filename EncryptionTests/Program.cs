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

            //while(true)
            {
                byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, };
                byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, };
                byte[] IV = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, };

                byte[] EncryptCode = new byte[0];
                byte[] DecryptCode = new byte[0];
                WopEx.GenerateCryptoCode(12345678, 20, ref EncryptCode, ref DecryptCode);
                wop_enc = new WopEx(Key, Salt, 12345678, EncryptCode, DecryptCode, WopEncMode.GenerateNewAlgorithm, 5, true);
                wop_dec = new WopEx(Key, Salt, 12345678, EncryptCode, DecryptCode, WopEncMode.GenerateNewAlgorithm, 5, true);

                //if (File.Exists("./temp.txt"))
                //    File.Delete("./temp.txt");

                Log("WopEx Algorithm with Shuffle algorithm enabled");
                Log("Key:  " + BitConverter.ToString(Key));
                Log("Salt: " + BitConverter.ToString(Salt));
                Log();

                Log("Encryption Algorithm:");
                ShowAlgorithm(wop_enc);

                byte[] Data = new byte[] { 1, 3, 3, 7, 1, 3, 3, 7, 1, 3, 3, 7, 1 };

                //while(true)
                {
                    EncDec(Data);
                }

            }
            Process.GetCurrentProcess().WaitForExit();
        }

        private static void ShowAlgorithm(WopEx wop)
        {
            /*Log("Instructions: " + wop.EncInstructions.Length);

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
            Log("=============================== Encrypting data ===============================");
            Log("Original Data:" + BitConverter.ToString(Data).Replace("-", " "));
            wop_enc.Encrypt(Data, 0, Data.Length, new MemoryStream(Data));
            Log("Encrypted Data:" + BitConverter.ToString(Data).Replace("-", " "));

            //Log("\r\n\r\n====================New Encryption Algorithm: ====================");
            //ShowAlgorithm(wop_enc);

            wop_dec.Decrypt(Data, 0, Data.Length, new MemoryStream(Data));
            Log("Decrypted data: " + BitConverter.ToString(Data).Replace("-", " "));
        }

        private static void RSA_Test()
        {
            //RSAEncryption GenPrivateKeyc = new RSAEncryption(4096, true);
            //GenPrivateKeyc.GeneratePrivateKey();
            //string PreGenPrivateKey = GenPrivateKeyc.PrivateKey;

            int BitSize = 4096;
            string PreGenPrivateKey = @"<RSAKeyValue>
                                            <Modulus>0tMchu/i6CJbovhHFdrPDS/KQGx2Fex83uAPv99IaezRnWCmO9ALJM4QnnMI/XcrclhOnf+ymv4ITwkw2a70itTEUAn4yqxhTt9zb0a0C9gCdTzlbijaGE/YRfJwnkvkSpxnZXPaY/wvOXVPPG3KoxPuhsFCj5kL0i36XYmbtEO4xcFgg1NisHU/ZP8+3YJzgKhSDbfPNO2Ayi0ItYwYVOqsRDqpSaBdx34LJzJASWdxTnel+P9lof57H5GZMTppkU4iSePNRB1LVW2dw/cPStLmmwsWclj905I1WS9dImAc6JDsEpQ/Rn8Mk+TLd/dZ/kO20rLbZid6a4L60FxI7dWjxuEaovqH9xM/+K+9TXm+CCp0KgCqgZHpyObrqdJjexP3KRXnq32pBEraL93agPQmxa3IQaoKxiMvtP/4nAxRTINNRt3uRCxfe2QJNyDz9mQ3bAe9Wld288EXGAG5UsUlNB2QAf26TTkr+6TIwZhzQYWXFs4Gq+lx2Gs55svWnZZ5sVhFleg1B8VYtjnyt0Jn11MqOJQDLOjuI/c9qdxNt3yb57xjyOUfRRznMIVPyyAP83oHBuV/kEkfP/4Iy6nDc+m5ee6vUXwj9cGIo7vWZHs+VqOh8m+Xk/F6uVINgd6YHVy6k0DEE2rj7PRVurJUo0sag2JPRFpgwvUfJRE=</Modulus>
                                            <Exponent>AQAB</Exponent>
                                            <P>2f/NiRY36c9y587A5osGJ2eawaf39wLAeMaA6jglfYhe4fsCiS0pMXYGxqRQoMI9V7ynhzRNtz/UOOPK9kIWREAUTuYbmjWNv7PAfcIbEK+S834+Ru8Nzr5C+8tmWDx+gVWljeAtfTawe2IWbdgNLah5JKtN0SuUVwIKT2NCmHL9gzEsZ5DzHOX+CgU1WxXB/3u9zfxt367BIrGSvL8tGkkBoglYxiIn21zr4C+BHAWqJAEzi6ZkTqh7Vg+S7k3/fpjp0e9/hHtkF9wOTE3CtRQ8wPkdB29Pojaywux2hz61M5ICloppgh1Ahvb2v+ij/Egngyc5M394EkWhFwS+XQ==</P>
                                            <Q>95MkysZwnH1Sma4zUasFJ8gD2t2y7HtxRkngZ3PV6vl3M8U+GF+mx/Be0JS2XkM6YGDFa/qplMUwNKayyVNmS2Urxf5QqGUD9X+sHLgpQOKsPVB+Elb+tmqbqmUAToYBw+Rp/YbZCsTGtGWzLmKai6E3QdgPK6tSdGf3IToX8i+egIgy5OK8QQkZ5qZ5bqDzp431rMGwCMYiY/VeG6ijQ8toGrf/zd+FyhjfFDoQ2+hSP1bQu0H4WszpMnUPOEkRbaL/YsJgLcP4cZYdIKiah/rfCfXVnvUboA6rZmSE7hNyRJqI4KL3MP+2IA9nJ35qnm6Lxk4fQtLt6XPeqb3ORQ==</Q>
                                            <DP>E0UCRQjavmcg8A6djINjct48lrujNolevA5H3OxDnBoO0QjgC4IbbwzQwoRJwDwLMhMx98iOyhDxUGoKScRDtZq4cNT0QahUNErOTA95Vvs+ERnqpViCLvEweJNdI5WNVR9d9/GF89h+txlPhDwhxhRrSOt/gGrKvPooMSZD/7fCYvNYynrMkpRd5ULamYeN02h7uZaDm88VsVxi7R40/WrQoyMSXsksHr7S9skcL37ssCwPA1wc57sK0+uigEASwnz/xhfWfL5vdZB1Dxeci2cTi7c5cqvLLTqKiKJgQ8ouODXC1s27T84IIyX3X7VPsYArRfOUodG1ql/PQnqf3Q==</DP>
                                            <DQ>wKXialvSQyOOBAI28uTmhRcyULxVP4mrEmvoT/gmTMtEg6eHc0XzLQARd7NQ2bbslRSYazbJgPeUVFQnKVxZbG/UiSQlNXQtiXqIvmxbxZ7dMnURNUo2uFHqwcQIYhILC5kRFPQ6rhODH9tHe9/ErMSNkBIFdBDDf8tq1ZM0EQQXDaNuHweEQANKAV4nffuGvipMMtshFSLAnhHP4ivup5F/d9MYHeZCYInMBRxOBCEa5yiyEhT6ogVzrQzEBCNviWXd3sasOtCU4iZSkhhA73E637BJQ4EttvXTUEEF45CESXgK7OpC+gDxgq8ZsPTBGHmjEHO4BbLG6PN+H42QFQ==</DQ>
                                            <InverseQ>lCP3LVBeCiOYkxZUiR6NCb14axj3EyQsYYvbXsQi1aDuZh/OovlbIRcpyqs07ZCE3jIYsJSjqUr/zLIjPmfhud/WvsJiCkKlTpvuEXvtwB4vlQo6kokrXQ/5ZMK3+lS7eJHJfJ73LMWb6ClPLrU4hh9+NxlrGiNZRPHIpybL5ZBaVPhkgg7EktZv08HBUmrJnLFdGCBmeQS1w4mgj7O+gICyFijR1bZlp+GvOHhqtSflzVZRbezE0Iz6olwyOPU//A5+GbRt0cU//r4Tc43JJqQ8BpybcRIOpTqz9ZVoowYJlY5iGJf4h0+qMQaelgR/yEPy7cYTQ4V4J+63Y3x/dA==</InverseQ>
                                            <D>MNDvTxNmwAeMnmzM0POsc8o4E7jJkwQCWf0ZyHzkIJrUYpOJiln+6pPIZ1gNodshNUXbVlxpt9fQhrSDGjSXrTndBwd4Ez3c/k1hRkfh0sg+sXTbTymobm62jmO3zf+WqewTSPuNew9ew/g007I8dIxd89f2GJgAk7dPvK7rXc88jpXbSi1ZsbBEcJdlsBbPtd/DuCdylDfWVXoeBSOeUrNQFjBbGJBIhrPZ00ageh64rsmnpcNFfkAVtFabWTnETgAAkolr8zSxR+Os3z5qzRGOkiH8HZgblgzJy4/bCeWla/h6oUawbBtpBym4L1wX+3ckcx81DC9h+lkGyI5F2FiMqRrXWhHlzvGIbZVbvWdrOGfD7K0NoKIa8xAtAa7Er9apUiP3EdNLNcI0M+l8/LlpFKGIcx7YSGVOD0Aac6UDlZFPOCc1NyK/EeF79x8r6ia+O8ezGlLy/5IODs0YT9+MzBgH40n9WUQtbiRq+vSghFjk0Wbtn7/3YsD+1L8YUrDvVVAlVzN3RDRDqHBFhL28C6LGTVqiBL377ItcSxMeI7Gj4vgf111jWcTcaYUlO6CZGosEs7hZRo4/fwLu86WFKAoI657I8bfskQQKJsaeUGd6ypVN1OoamhdyCuN8gk8q40p66lTAeDmmKMR+01xYlsVawFiKYdca9cW/FxE=</D>
                                        </RSAKeyValue>";

            RSAEncryption Private_Rsa = new RSAEncryption(BitSize, "", PreGenPrivateKey, true);

            //When generating, only the modulus and Exponent should be made public, nothing else
            string PublicKeyA = Private_Rsa.GeneratePublicKey();


            RSAEncryption Public_Rsa = new RSAEncryption(BitSize, PublicKeyA, "", true);


            string TestData = "Helllo, This is A, let's hope this message arrived well";
            byte[] EncryptedData = Private_Rsa.Encrypt(new byte[] { 1,3,3,7 }, 0, 4);
            //byte[] SignedData = Public_Rsa.SignData(ASCIIEncoding.ASCII.GetBytes(TestData));


            byte[] DecryptedData = Public_Rsa.Decrypt(EncryptedData, 0, EncryptedData.Length);
        }
    }
}