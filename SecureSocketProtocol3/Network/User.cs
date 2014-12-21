using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Network
{
    public class User
    {
        //client/server information
        public string Username { get; set; }
        public string Password { get; set; }
        public List<byte[]> PrivateKeys { get; private set; }
        public byte[] PublicKey { get; set; }

        //server information
        public string EncryptedHash { get; set; }

        /// <summary>
        /// The encrypted Public Key we will expect from the correct user, save this in a database to indentify the user
        /// </summary>
        public byte[] EncryptedPublicKey { get; set; }

        /// <summary>
        /// The MAZE Instance, contains the keys for the session
        /// </summary>
        public Mazing MazeHandshake { get; private set; }

        internal User()
        {
            Username = "";
            Password = "";
            PrivateKeys = new List<byte[]>();
            PublicKey = new byte[0];
        }

        /// <summary>
        /// Create a new instance of User
        /// </summary>
        /// <param name="Username">The Username for the user</param>
        /// <param name="Password">The Password for the user</param>
        /// <param name="PrivateKeys">The Private Key(s) that are being used to Encrypt the Session</param>
        /// <param name="PublicKey">The Public Key to indentify the user</param>
        public User(string Username, string Password, List<Stream> PrivateKeys, Stream PublicKey)
        {
            this.Username = Username;
            this.Password = Password;

            this.PrivateKeys = new List<byte[]>();
            foreach (Stream stream in PrivateKeys)
                this.PrivateKeys.Add(ReadAllBytes(stream));

            this.PublicKey = ReadAllBytes(PublicKey);
        }

        internal byte[] ReadAllBytes(Stream stream)
        {
            byte[] temp = new byte[stream.Length];
            int writeOffset = 0;
            while (writeOffset != stream.Length)
            {
                int read = stream.Read(temp, writeOffset, (int)stream.Length - writeOffset);
                writeOffset += read;
            }
            return temp;
        }

        /// <summary>
        /// Generate the keys to identify the user and encrypt the network session
        /// </summary>
        public void GenKey(SessionSide side)
        {
            if(side == SessionSide.Server)
                MazeHandshake = new ServerMaze();
            else
                MazeHandshake = new ClientMaze();

            MazeHandshake.SetLoginData(Username, Password, PrivateKeys, PublicKey);
            MazeHandshake.SetMazeKey();

            //encrypt the public key with WopEx
            EncryptedPublicKey = MazeHandshake.GetEncryptedPublicKey();
            EncryptedHash = BitConverter.ToString(SHA512Managed.Create().ComputeHash(EncryptedPublicKey, 0, EncryptedPublicKey.Length)).Replace("-", "");
        }

        /// <summary>
        /// Get the user information you need to store in a database to indentify the user
        /// </summary>
        /// <returns></returns>
        public UserDbInfo GetUserDbInfo()
        {
            return new UserDbInfo(MazeHandshake.Username, MazeHandshake.Password, EncryptedHash, MazeHandshake.MazeKey, MazeHandshake.PrivateSalt, MazeHandshake.PublicKeyData, Username);
        }

        public class UserDbInfo
        {
            public string UsernameStr { get; private set; }
            public BigInteger Username { get; private set; }
            public BigInteger Password { get; private set; }
            public string EncryptedHash { get; private set; }
            public BigInteger Key { get; private set; }
            public BigInteger PrivateSalt { get; private set; }
            public byte[] PublicKey { get; private set; }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="EncryptedHash"></param>
            /// <param name="Key"></param>
            /// <param name="PrivateSalt"></param>
            /// <param name="PublicKey"></param>
            public UserDbInfo(BigInteger Username, BigInteger Password, string EncryptedHash, BigInteger Key, BigInteger PrivateSalt, byte[] PublicKey, string UsernameStr)
            {
                this.Username = Username;
                this.Password = Password;
                this.EncryptedHash = EncryptedHash;
                this.Key = Key;
                this.PrivateSalt = PrivateSalt;
                this.PublicKey = PublicKey;
                this.UsernameStr = UsernameStr;
            }

            /// <summary>
            /// serialize the UserDbInfo in a Base64 string
            /// </summary>
            /// <returns></returns>
            public string Serialize()
            {
                using (PayloadWriter pw = new PayloadWriter())
                {
                    pw.WriteString(UsernameStr);
                    pw.WriteString(EncryptedHash);

                    pw.WriteBigInteger(Username);
                    pw.WriteBigInteger(Password);
                    pw.WriteBigInteger(Key);
                    pw.WriteBigInteger(PrivateSalt);

                    pw.WriteInteger(PublicKey.Length);
                    pw.WriteBytes(PublicKey);

                    return Convert.ToBase64String(pw.ToByteArray());
                }
            }

            public UserDbInfo Deserialize(string SerializedData)
            {
                using(PayloadReader pr = new PayloadReader(Convert.FromBase64String(SerializedData)))
                {
                    string userStr = pr.ReadString();
                    string EncryptedHashStr = pr.ReadString();
                    BigInteger userInt = pr.ReadBigInteger();
                    BigInteger passInt = pr.ReadBigInteger();
                    BigInteger keyInt = pr.ReadBigInteger();
                    BigInteger saltInt = pr.ReadBigInteger();
                    byte[] pubKey = pr.ReadBytes(pr.ReadInteger());

                    return new UserDbInfo(userInt, passInt, EncryptedHashStr, keyInt, saltInt, pubKey, userStr);
                }
            }
        }
    }
}