using SecureSocketProtocol3.Encryptions;
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

        static void Main(string[] args)
        {
            MazeErrorCode clientError = MazeErrorCode.Error;
            MazeErrorCode serverError = MazeErrorCode.Error;

            Server_Users = new List<User>();

            User user = new User();
            user.Username = "UserTest";
            user.Password = "UserPasS";
            user.PublicKey = File.ReadAllBytes(@"F:\Untitled.png");

            foreach (string file in Directory.GetFiles(@"F:\", "*.dll"))
            {
                if (user.PrivateKeys.Count == 3)
                    break;
                user.PrivateKeys.Add(File.ReadAllBytes(file));
            }

            byte[] ClientResponseData = new byte[0];
            byte[] ServerResponseData = new byte[0];

            ClientMaze client = new ClientMaze();

            //set the server variables
            ServerMaze server = new ServerMaze();
            server.onFindKeyInDatabase += server_onFindKeyInDatabase;

            Console.WriteLine("[Server] Creating user table...");
            user.GenServerKey();
            Server_Users.Add(user);
            Console.WriteLine(".............................................................");

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

            //3. Client generates a key to use for the server
            List<byte[]> PrivateKeys = new List<byte[]>();
            foreach (string file in Directory.GetFiles(@"F:\", "*.dll"))
            {
                if (PrivateKeys.Count == 3)
                    break;
                PrivateKeys.Add(File.ReadAllBytes(file));
            }


            //in this example we will simply keep this simple, so no additional encryption(s) will be used here except the one that is being used by the handshake it self
            Console.WriteLine("[Client] Setting login data...");
            client.SetLoginData(user.Username, user.Password, PrivateKeys, user.PublicKey);


            Console.WriteLine("[Client] Calculating the key");
            BigInteger mazeKey = client.SetMazeKey();

            Console.WriteLine("[Client] Encrypting the public key & sending public key");
            byte[] encryptedPublicKey = client.GetEncryptedPublicKey();



            Console.WriteLine("[Server] Received encrypted public key");
            serverError = server.onReceiveData(encryptedPublicKey, ref ServerResponseData);
            if (serverError != MazeErrorCode.Success)
            {
                Console.WriteLine("[Server] Encrypted Public Key was not found in database or something else went wrong");
                Process.GetCurrentProcess().WaitForExit();
            }
            Console.WriteLine("[Server] Sending back response to client len:" + ServerResponseData.Length);

            Console.WriteLine("[Client] Received response from server... len:" + ServerResponseData.Length + ", sending response back...");
            clientError = client.onReceiveData(ServerResponseData, ref ClientResponseData);
            if (clientError != MazeErrorCode.Success && clientError != MazeErrorCode.Finished)
            {
                Console.WriteLine("[Client] Incorrect response from server");
                Process.GetCurrentProcess().WaitForExit();
            }

            Console.WriteLine("[Server] Received response from client len:" + ServerResponseData.Length);
            serverError = server.onReceiveData(ClientResponseData, ref ServerResponseData);
            if (serverError != MazeErrorCode.Success && serverError != MazeErrorCode.Finished)
            {
                Console.WriteLine("[Server] Incorrect response from client");
                Process.GetCurrentProcess().WaitForExit();
            }
            Console.WriteLine("[Client] Applied the key to the encryption");
            Console.WriteLine("[Server] Applied the key to the encryption");

            Console.WriteLine("[Client-Key] " + BitConverter.ToString(client.wopEx.Key) + "\r\n");
            Console.WriteLine("[Client-Salt] " + BitConverter.ToString(client.wopEx.Salt) + "\r\n\r\n");
            Console.WriteLine("[Server-Key] " + BitConverter.ToString(server.wopEx.Key) + "\r\n");
            Console.WriteLine("[Server-Salt] " + BitConverter.ToString(server.wopEx.Salt));

            Console.WriteLine("Done... Authenticated without sending login data");
            Process.GetCurrentProcess().WaitForExit();
        }

        static bool server_onFindKeyInDatabase(string EncryptedHash, ref byte[] Key, ref byte[] Salt, ref byte[] PublicKey)
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

                Console.WriteLine("[Server] Setting up login data for user, " + Username);
                ServerHandshake.SetLoginData(Username, Password, PrivateKeys, PublicKey);
                Console.WriteLine("[Server] Generating key for user, " + Username);
                ServerHandshake.SetMazeKey();

                //encrypt the public key with WopEx
                EncryptedPublicKey = new byte[PublicKey.Length];
                Array.Copy(PublicKey, EncryptedPublicKey, PublicKey.Length);
                ServerHandshake.GetWopEncryption().Encrypt(EncryptedPublicKey, 0, EncryptedPublicKey.Length); //encrypt the public key
                EncryptedHash = BitConverter.ToString(SHA512Managed.Create().ComputeHash(EncryptedPublicKey, 0, EncryptedPublicKey.Length)).Replace("-", "");
            }
        }
    }
}