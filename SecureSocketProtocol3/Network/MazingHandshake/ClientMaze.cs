using SecureSocketProtocol3.Encryptions;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Network.MazingHandshake
{
    public class ClientMaze : Mazing
    {
        public WopEx wopEx;

        public ClientMaze()
            : base(new Size(512, 512), 10, 30)
        {

        }

        public override MazeErrorCode onReceiveData(byte[] Data, ref byte[] ResponseData)
        {
            ResponseData = new byte[0];
            switch (base.Step)
            {
                case 1:
                {
                    if (Data.Length != 32)
                    {
                        return MazeErrorCode.Error;
                    }

                    wopEx = base.GetWopEncryption();
                    wopEx.Decrypt(Data, 0, Data.Length);

                    BigInteger server_prime = new BigInteger(Data);
                    if (server_prime.isProbablePrime())
                    {
                        //verify the prime from the server
                        BigInteger server_Prime_test = BigInteger.genPseudoPrime(256, 50, new Random(BitConverter.ToInt32(wopEx.Key, 0)));

                        if (server_prime != server_Prime_test)
                        {
                            //Attacker detected ?
                            return MazeErrorCode.Error;
                        }

                        //successful
                        //generate another prime and send it back
                        BigInteger client_Prime = BigInteger.genPseudoPrime(256, 50, new Random(server_prime.IntValue()));
                        byte[] primeData = client_Prime.getBytes();
                        wopEx.Encrypt(primeData, 0, primeData.Length);
                        ResponseData = primeData;

                        BigInteger key = base.ModKey(server_prime, client_Prime);
                        //apply key to encryption
                        ApplyKey(wopEx, key);

                        base.FinalKey = wopEx.Key;
                        base.FinalSalt = wopEx.Salt;

                        Step++;
                        return MazeErrorCode.Finished;
                    }
                    else
                    {
                        //connection failed, using old keys ?
                        return MazeErrorCode.Error;
                    }
                }
            }

            return MazeErrorCode.Success;
        }
    }
}