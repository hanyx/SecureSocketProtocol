using SecureSocketProtocol3.Security.Encryptions;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Network.MazingHandshake
{
    public class ServerMaze : Mazing
    {
        private MazeErrorCode LastErrorCode = MazeErrorCode.Success;
        private byte[] _publicKeyResponse = null;

        public delegate bool FindKeyInDatabaseCallback(string EncryptedHash, ref byte[] Key, ref byte[] Salt, ref byte[] PublicKey, ref string Username);
        public event FindKeyInDatabaseCallback onFindKeyInDatabase;

        public WopEx wopEx;
        private BigInteger server_Prime;
        private BigInteger client_Prime;

        public string Username { get; private set; }

        public ServerMaze(Size size, int MazeCount, int MazeSteps)
            : base(size, MazeCount, MazeSteps)
        {

        }

        public override MazeErrorCode onReceiveData(byte[] Data, ref byte[] ResponseData)
        {
            ResponseData = new byte[0];

            if (LastErrorCode != MazeErrorCode.Success)
            {
                //don't continue if the client/server messed something up
                return LastErrorCode;
            }

            switch (base.Step)
            {
                case 1:
                {
                    //step 2
                    if (Data.Length != Mazing.ByteCode.Length)
                    {
                        SysLogger.Log("[MazeHandShake][Server] ByteCode Length Missmatch", SysLogType.Debug);
                        return MazeErrorCode.WrongByteCode;
                    }

                    for (int i = 0; i < Mazing.ByteCode.Length; i++)
                    {
                        if (Mazing.ByteCode[i] != Data[i])
                        {
                            SysLogger.Log("[MazeHandShake][Server] WrongByteCode from client", SysLogType.Debug);
                            return MazeErrorCode.WrongByteCode;
                        }
                    }
                    Step++;
                    break;
                }
                case 2:
                {
                    if (onFindKeyInDatabase == null) //programmer error
                    {
                        SysLogger.Log("[MazeHandShake][Server] onFindKeyInDatabase is null", SysLogType.Debug);
                        ResponseData = GetFailResponseData(); //not encrypted, client knows this will fail
                        return MazeErrorCode.Error;
                    }

                    string EncHashedMsg = BitConverter.ToString(SHA512Managed.Create().ComputeHash(Data, 0, Data.Length)).Replace("-", "");
                    byte[] _key = new byte[0];
                    byte[] _salt = new byte[0];
                    byte[] _publicKey = new byte[0];
                    string _userName = "";

                    if (onFindKeyInDatabase(EncHashedMsg, ref _key, ref _salt, ref _publicKey, ref _userName))
                    {
                        this.PublicKeyData = TrimArray(_publicKey, Mazing.MAX_KEY_SIZE);
                        this.wopEx = base.GetWopEncryption(_key, _salt);

                        base.FinalKey = _key;
                        base.FinalSalt = _salt;

                        //let's try to decrypt the data, should go successful
                        wopEx.Decrypt(Data, 0, Data.Length, new MemoryStream(Data));

                        if (Data.Length != _publicKey.Length)
                        {
                            SysLogger.Log("[MazeHandShake][Server] Public key length missmatch", SysLogType.Debug);
                            //key size not the same... strange
                            ResponseData = GetFailResponseData();
                            return MazeErrorCode.Error;
                        }

                        for (int i = 0; i < _publicKey.Length; i++)
                        {
                            if (Data[i] != _publicKey[i])
                            {
                                SysLogger.Log("[MazeHandShake][Server] Public key missmatch", SysLogType.Debug);
                                //public key did not match... strange
                                ResponseData = GetFailResponseData();
                                return MazeErrorCode.Error;
                            }
                        }

                        //encryption / public key went successful for now
                        this.server_Prime = BigInteger.genPseudoPrime(256, 50, new Random(BitConverter.ToInt32(_key, 0)));
                        byte[] primeData = server_Prime.getBytes();
                        wopEx.Encrypt(primeData, 0, primeData.Length, new MemoryStream(primeData));
                        ResponseData = primeData;

                        this.Username = _userName;

                        Step++;
                    }
                    else
                    {
                        SysLogger.Log("[MazeHandShake][Server] No user key found in database", SysLogType.Debug);
                        ResponseData = GetFailResponseData();
                        return MazeErrorCode.UserKeyNotFound;
                    }
                    break;
                }
                case 3:
                {
                    //response back from client with his prime number
                    wopEx.Decrypt(Data, 0, Data.Length, new MemoryStream(Data));
                    
                    this.client_Prime = new BigInteger(Data);
                    if (this.client_Prime.isProbablePrime())
                    {
                        //verify the prime from the client
                        BigInteger client_Prime_test = BigInteger.genPseudoPrime(256, 50, new Random(this.server_Prime.IntValue()));
                        
                        if (this.client_Prime != client_Prime_test)
                        {
                            //Attacker detected ?
                            SysLogger.Log("[MazeHandShake][Server] Man-In-The-Middle detected", SysLogType.Debug);
                            return MazeErrorCode.Error;
                        }

                        BigInteger key = base.ModKey(server_Prime, client_Prime);
                        //apply key to encryption
                        ApplyKey(wopEx, key);

                        base.FinalKey = wopEx.Key;
                        base.FinalSalt = wopEx.Salt;

                        return MazeErrorCode.Finished;
                    }
                    else
                    {
                        SysLogger.Log("[MazeHandShake][Server] Invalid response", SysLogType.Debug);
                        return MazeErrorCode.Error;
                    }
                }
            }
            return MazeErrorCode.Success;
        }

        private byte[] GetFailResponseData()
        {
            Random rnd = new Random();
            BigInteger retPrime = BigInteger.genPseudoPrime(64, 30, rnd);
            do
            {
                retPrime++;
            } while (retPrime.isProbablePrime());
            return retPrime.getBytes(); //not encrypted, client knows this will fail
        }
    }
}