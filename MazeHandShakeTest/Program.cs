using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MazeHandShakeTest
{
    class Program
    {
        /// <summary>
        /// A tiny database of users used by the server
        /// </summary>
        private static List<User> Server_Users;

        private static Random Random = new Random(452354453);
        private static byte[] GetRandomBytes(int length)
        {
            byte[] temp = new byte[length];
            Random.NextBytes(temp);
            return temp;
        }

        static void Main(string[] args)
        {
            try
            {
                MazeErrorCode clientError = MazeErrorCode.Error;
                MazeErrorCode serverError = MazeErrorCode.Error;
                int multiplier = 100;

                while (true)
                {
                    Server_Users = new List<User>();

                    //create users
                    User temp_user = new User();
                    temp_user.Username = ASCIIEncoding.ASCII.GetString(GetRandomBytes(20));
                    temp_user.Password = ASCIIEncoding.ASCII.GetString(GetRandomBytes(20));
                    temp_user.PublicKey = GetRandomBytes(128 * multiplier); //File.ReadAllBytes("./Data/PublicKey1.dat"));

                    //for (int i = 0; i < temp_user.PublicKey.Length; i++)
                    //    temp_user.PublicKey[i] = (byte)(i % 100);

                    temp_user.PrivateKeys.Add(GetRandomBytes(128 * multiplier)); //File.ReadAllBytes("./Data/PrivateKey1.dat"));
                    temp_user.PrivateKeys.Add(GetRandomBytes(128 * multiplier)); //(File.ReadAllBytes("./Data/PrivateKey2.dat"));

                    Console.WriteLine("[Server] Creating user table...");
                    temp_user.GenServerKey();
                    Server_Users.Add(temp_user);

                    Console.WriteLine(".............................................................");

                    foreach (User User in Server_Users)
                    {
                        Stopwatch sw = Stopwatch.StartNew();
                        ClientMaze client = new ClientMaze();
                        ServerMaze server = new ServerMaze();
                        server.onFindKeyInDatabase += server_onFindKeyInDatabase;


                        byte[] ClientResponseData = new byte[0];
                        byte[] ServerResponseData = new byte[0];

                        //1. Send server the bytecode
                        byte[] byteCode = client.GetByteCode();
                        Console.WriteLine("[Client] Sending ByteCode to server");


                        //2. Server receives the ByteCode
                        serverError = server.onReceiveData(byteCode, ref ServerResponseData);
                        if (serverError == MazeErrorCode.Success)
                        {
                            Console.WriteLine("[Server] ByteCode is correct, continue on with handshake");
                        }
                        else
                        {
                            Console.WriteLine("[Server] ByteCode is not correct, disconnecting...");
                        }

                        //in this example we will simply keep this simple, so no additional encryption(s) will be used here except the one that is being used by the handshake it self
                        Console.WriteLine("[Client] Setting login data... username:" + User.Username);
                        client.SetLoginData(User.Username, User.Password, User.PrivateKeys, User.PublicKey);


                        Console.WriteLine("[Client] Calculating the key");
                        BigInteger mazeKey = client.SetMazeKey();

                        Console.WriteLine("[Client] Encrypting the public key & sending public key");
                        byte[] encryptedPublicKey = client.GetEncryptedPublicKey();



                        Console.WriteLine("[Server] Received encrypted public key");
                        serverError = server.onReceiveData(encryptedPublicKey, ref ServerResponseData);
                        if (serverError != MazeErrorCode.Success)
                        {
                            Console.WriteLine("[Server] Encrypted Public Key was not found in database or something else went wrong");
                            continue;//Process.GetCurrentProcess().WaitForExit();
                        }
                        Console.WriteLine("[Server] Sending back response to client len:" + ServerResponseData.Length);

                        Console.WriteLine("[Client] Received response from server... len:" + ServerResponseData.Length + ", sending response back...");
                        clientError = client.onReceiveData(ServerResponseData, ref ClientResponseData);
                        if (clientError != MazeErrorCode.Success && clientError != MazeErrorCode.Finished)
                        {
                            Console.WriteLine("[Client] Incorrect response from server");
                            continue;//Process.GetCurrentProcess().WaitForExit();
                        }

                        Console.WriteLine("[Server] Received response from client len:" + ServerResponseData.Length);
                        serverError = server.onReceiveData(ClientResponseData, ref ServerResponseData);
                        if (serverError != MazeErrorCode.Success && serverError != MazeErrorCode.Finished)
                        {
                            Console.WriteLine("[Server] Incorrect response from client");
                            continue;//Process.GetCurrentProcess().WaitForExit();
                        }
                        Console.WriteLine("[Client] Applied the key to the encryption");
                        Console.WriteLine("[Server] Applied the key to the encryption");

                        Console.WriteLine("[Client-Key] " + BitConverter.ToString(client.wopEx.Key) + "\r\n");
                        Console.WriteLine("[Client-Salt] " + BitConverter.ToString(client.wopEx.Salt) + "\r\n\r\n");
                        Console.WriteLine("[Server-Key] " + BitConverter.ToString(server.wopEx.Key) + "\r\n");
                        Console.WriteLine("[Server-Salt] " + BitConverter.ToString(server.wopEx.Salt));

                        sw.Stop();
                        Console.WriteLine("Done... Authenticated without sending login data, completed in " + sw.Elapsed);
                    }
                }
                Process.GetCurrentProcess().WaitForExit();
            }
            catch { }
        }

        static bool server_onFindKeyInDatabase(string EncryptedHash, ref byte[] Key, ref byte[] Salt, ref byte[] PublicKey, ref string Username)
        {
            foreach (User user in Server_Users)
            {
                if (user.EncryptedHash == EncryptedHash)
                {
                    Key = user.ServerHandshake.MazeKey.getBytes();
                    Salt = user.ServerHandshake.PrivateSalt.getBytes();
                    PublicKey = user.PublicKey;
                    Username = user.Username;
                    return true;
                }
            }
            return false;
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

                Console.WriteLine("[Server] Setting up login data for user, ");// + Username);
                ServerHandshake.SetLoginData(Username, Password, PrivateKeys, PublicKey);
                Console.WriteLine("[Server] Generating key for user, ");// + Username);
                ServerHandshake.SetMazeKey();

                //encrypt the public key with WopEx
                EncryptedPublicKey = ServerHandshake.GetEncryptedPublicKey(); //encrypt the public key
                EncryptedHash = BitConverter.ToString(SHA512Managed.Create().ComputeHash(EncryptedPublicKey, 0, EncryptedPublicKey.Length)).Replace("-", "");
            }
        }
    }
}