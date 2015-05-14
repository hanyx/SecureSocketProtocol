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
    }
}