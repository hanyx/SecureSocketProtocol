using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SSPTests
{
    [TestClass()]
    public class MazeTests
    {
        [TestMethod()]
        public void Test_MazeAuthentication()
        {
            MazeErrorCode clientError = MazeErrorCode.Error;
            MazeErrorCode serverError = MazeErrorCode.Error;

            List<User> Server_Users = new List<User>();

            //create users
            User temp_user = new User();
            temp_user.Username = "";
            temp_user.Password = "";
            temp_user.PublicKey = File.ReadAllBytes("./Data/PublicKey1.dat");

            temp_user.PrivateKeys.Add(File.ReadAllBytes("./Data/PrivateKey1.dat"));
            temp_user.PrivateKeys.Add(File.ReadAllBytes("./Data/PrivateKey2.dat"));

            temp_user.GenServerKey();
            Server_Users.Add(temp_user);

            Console.WriteLine(".............................................................");

            foreach (User User in Server_Users)
            {
                Stopwatch sw = Stopwatch.StartNew();
                ClientMaze client = new ClientMaze();
                ServerMaze server = new ServerMaze();
                server.onFindKeyInDatabase += (string EncryptedHash, ref byte[] Key, ref byte[] Salt, ref byte[] PublicKey) =>
                {
                    foreach (User user in Server_Users)
                    {
                        if (user.EncryptedHash == EncryptedHash)
                        {
                            Key = user.ServerHandshake.MazeKey.getBytes();
                            Salt = user.ServerHandshake.PrivateSalt.getBytes();
                            PublicKey = user.PublicKey;
                            return true;
                        }
                    }
                    return false;
                };


                byte[] ClientResponseData = new byte[0];
                byte[] ServerResponseData = new byte[0];

                //1. Send server the bytecode
                byte[] byteCode = client.GetByteCode();

                //2. Server receives the ByteCode
                serverError = server.onReceiveData(byteCode, ref ServerResponseData);
                if (serverError != MazeErrorCode.Success)
                {
                    throw new Exception("[Server] ByteCode is not correct, disconnecting...");
                }

                //in this example we will simply keep this simple, so no additional encryption(s) will be used here except the one that is being used by the handshake it self
                client.SetLoginData(User.Username, User.Password, User.PrivateKeys, User.PublicKey);
                BigInteger mazeKey = client.SetMazeKey();
                byte[] encryptedPublicKey = client.GetEncryptedPublicKey();


                serverError = server.onReceiveData(encryptedPublicKey, ref ServerResponseData);
                if (serverError != MazeErrorCode.Success)
                {
                    throw new Exception("[Server] Encrypted Public Key was not found in database or something else went wrong");
                }

                clientError = client.onReceiveData(ServerResponseData, ref ClientResponseData);
                if (clientError != MazeErrorCode.Success && clientError != MazeErrorCode.Finished)
                {
                    throw new Exception("[Client] Incorrect response from server");
                }

                serverError = server.onReceiveData(ClientResponseData, ref ServerResponseData);
                if (serverError != MazeErrorCode.Success && serverError != MazeErrorCode.Finished)
                {
                    throw new Exception("[Server] Incorrect response from client");
                }
            }
        }


        public class User
        {
            //client/server information
            public string Username { get; set; }
            public string Password { get; set; }
            public List<byte[]> PrivateKeys { get; private set; }
            public byte[] PublicKey { get; set; }

            //server information
            public string EncryptedHash { get; set; }
            public byte[] EncryptedPublicKey { get; set; }

            public ServerMaze ServerHandshake { get; set; }

            public User()
            {
                Username = "";
                Password = "";
                PrivateKeys = new List<byte[]>();
                PublicKey = new byte[0];
            }

            public void GenServerKey()
            {
                ServerHandshake = new ServerMaze();
                ServerHandshake.SetLoginData(Username, Password, PrivateKeys, PublicKey);
                ServerHandshake.SetMazeKey();

                //encrypt the public key with WopEx
                EncryptedPublicKey = ServerHandshake.GetEncryptedPublicKey(); //encrypt the public key
                EncryptedHash = BitConverter.ToString(SHA512Managed.Create().ComputeHash(EncryptedPublicKey, 0, EncryptedPublicKey.Length)).Replace("-", "");
            }
        }
    }
}