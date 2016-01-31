using SecureSocketProtocol3.Security.Encryptions;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;

/*
    The MIT License (MIT)

    Copyright (c) 2016 AnguisCaptor

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace SecureSocketProtocol3.Network.MazingHandshake
{
    public class ClientMaze : Mazing
    {
        public WopEx wopEx;

        public ClientMaze(Size size, int MazeCount, int MazeSteps)
            : base(size, MazeCount, MazeSteps)
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
                        SysLogger.Log("[MazeHandShake][Server] Receive Length missmatch", SysLogType.Debug);
                        return MazeErrorCode.Error;
                    }

                    wopEx = base.GetWopEncryption();
                    wopEx.Decrypt(Data, 0, Data.Length, new MemoryStream(Data));

                    BigInteger server_prime = new BigInteger(Data);
                    if (server_prime.isProbablePrime())
                    {
                        //verify the prime from the server
                        BigInteger server_Prime_test = BigInteger.genPseudoPrime(256, 50, new Random(BitConverter.ToInt32(wopEx.Key, 0)));

                        if (server_prime != server_Prime_test)
                        {
                            //Attacker detected ?
                            SysLogger.Log("[MazeHandShake][Server] Man-In-The-Middle detected", SysLogType.Debug);
                            return MazeErrorCode.Error;
                        }

                        //successful
                        //generate another prime and send it back
                        BigInteger client_Prime = BigInteger.genPseudoPrime(256, 50, new Random(server_prime.IntValue()));

                        byte[] primeData = client_Prime.getBytes();
                        wopEx.Encrypt(primeData, 0, primeData.Length, new MemoryStream(primeData));
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
                        SysLogger.Log("[MazeHandShake][Server] Invalid received data", SysLogType.Debug);
                        return MazeErrorCode.Error;
                    }
                }
            }

            return MazeErrorCode.Success;
        }
    }
}