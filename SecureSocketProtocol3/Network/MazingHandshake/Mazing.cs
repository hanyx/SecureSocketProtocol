using SecureSocketProtocol3.Encryptions;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using vicMazeGen;

namespace SecureSocketProtocol3.Network.MazingHandshake
{
    /// <summary>
    /// The Mazing Handshake is a custom handshake to replace RSA & Diffie-Hellman
    /// </summary>
    public abstract class Mazing
    {
        /// <summary>
        /// A constant byte code for the handshake
        /// </summary>
        protected static byte[] ByteCode
        {
            get
            {
                return new byte[]
                {
                    83, 105, 17, 132, 126, 6, 163, 17, 170, 26, 54, 
                    104, 190, 231, 93, 47, 156, 203, 211, 156, 12, 84, 
                    168, 149, 172, 159, 246, 64, 35, 124, 106, 179,
                };
            }
        }

        public const int MAX_KEY_SIZE = 32768;
        public int Step { get; protected set; }
        public abstract MazeErrorCode onReceiveData(byte[] Data, ref byte[] ResponseData);
        public Size MazeSize { get; private set; }
        public int MazeCount { get; private set; }
        public int MazeSteps { get; private set; }


        private byte[] _publicKeyData;
        public byte[] PublicKeyData
        {
            get { return _publicKeyData; }
            private set { _publicKeyData = value; }
        }

        public BigInteger PrivateSalt { get; private set; }
        public BigInteger Username { get; private set; }
        public BigInteger Password { get; private set; }

        private BigInteger _mazeKey;
        public BigInteger MazeKey
        {
            get { return _mazeKey; }
            private set { _mazeKey = value; }
        }

        public byte[] FinalKey { get; protected set; }
        public byte[] FinalSalt { get; protected set; }

        /// <summary>
        /// Initialize the mazing handshake
        /// </summary>
        /// <param name="size">The size of the actual maze</param>
        /// <param name="MazeCount">The amount of maze's we should generate, higher value = better</param>
        /// <param name="MazeSteps">How many steps we should take in each generated maze, higher value = better</param>
        public Mazing(Size size, int MazeCount, int MazeSteps)
        {
            if (size.Width < 128 || size.Height < 128)
                throw new ArgumentException("The size for the maze should be atleast 128x128");
            if (MazeCount < 5)
                throw new ArgumentException("There must be atleast 5 maze's we should generate");
            //if ((MazeSteps * MazeCount) < (size.Width * size.Height))
            //    throw new Exception("");

            this.MazeSize = size;
            this.MazeCount = MazeCount;
            this.MazeSteps = MazeSteps;
            this.Step = 1;
            this.PrivateSalt = new BigInteger();
            this.Username = new BigInteger();
            this.Password = new BigInteger();
            this.MazeKey = new BigInteger();
        }

        public BigInteger PrivateKeyToSalt(byte[] PrivateData)
        {
            BigInteger bigInt = new BigInteger();

            int seed = 0x0FFFFAAA;
            for(int i = 0; i < (PrivateData.Length / 4) - 1; i++)
            {
                seed += BitConverter.ToInt32(PrivateData, i * 4);
            }

            bigInt.genRandomBits(128, new Random(seed));

            BigInteger temp = seed;
            for (int i = 0; i < PrivateData.Length / 8; i++)
            {
                if ((i * 8) + 8 > PrivateData.Length)
                    break;

                bigInt += temp >> 8;
                temp += equK(bigInt, temp + BitConverter.ToUInt64(PrivateData, i * 8), seed);
                bigInt += temp;
            }

            return bigInt;
        }

        public void SetLoginData(string Username, string Password, List<byte[]> PrivateKeyData, byte[] PublicKeyData)
        {
            //step 3
            if (PublicKeyData.Length < 128)
                throw new ArgumentException("The PublicKeyData must contain atleast 128 bytes");

            SHA512 hasher = SHA512Managed.Create();

            //trim down the public key if bigger then 32768
            this._publicKeyData = TrimArray(PublicKeyData, MAX_KEY_SIZE);

            for (int i = 0; i < PrivateKeyData.Count; i++)
            {
                if (PrivateKeyData[i].Length < 128)
                    throw new ArgumentException("The Private Key must contain atleast 128 bytes");

                byte[] tempPrivKey = CloneByteArray(PrivateKeyData[i]);
                byte[] privHash = hasher.ComputeHash(tempPrivKey, 0, 100);
                int privHashNr_1 = BitConverter.ToInt32(privHash, 26);
                int privHashNr_2 = BitConverter.ToInt32(privHash, 32);
                PrivateSalt = cubicEqu(PrivateKeyData.Count, PrivateKeyToSalt(tempPrivKey), privHashNr_1, privHashNr_1, privHashNr_2, PrivateSalt);
            }

            this.Username = new BigInteger(hasher.ComputeHash(UnicodeEncoding.Unicode.GetBytes(Username))) ^ PrivateSalt;
            this.Password = (new BigInteger(hasher.ComputeHash(UnicodeEncoding.Unicode.GetBytes(Password))) ^ this.Username) ^ PrivateSalt;

            this.PrivateSalt += this.Username + this.Password;

            for (int i = 0; i < 5; i++)
            {
                this.Password ^= new BigInteger(hasher.ComputeHash(UnicodeEncoding.Unicode.GetBytes(Password + this.Password)));
            }
        }

        protected BigInteger equK(BigInteger P, BigInteger O, int C)
        {
            return (P / (O * O * O)) + C;
        }

        private BigInteger cubicEqu(BigInteger a, BigInteger b, BigInteger c, BigInteger d, int x, BigInteger o)
        {
            return ((a * (x * x * x)) + (b * (x * x)) + (c * x) + d) + o;
        }

        /// <summary>
        /// Set the Maze Key and get the Maze Key to apply it to the encryption algorithm
        /// </summary>
        /// <returns></returns>
        public BigInteger SetMazeKey()
        {
            //Step 5/6 - Walking the Maze
            int beginPosX = equK(Username, (BigInteger)Username.IntValue(), PrivateSalt.IntValue()).IntValue() % (this.MazeSize.Width / 2) + 3;
            int beginPosY = equK(Password, (BigInteger)Username.IntValue(), PrivateSalt.IntValue()).IntValue() % (this.MazeSize.Height / 2) + 3;
            bool Back = false;

            int WalkSize = 30;

            this.MazeKey = new BigInteger();

            for (int i = 0, j = 1, k = 3, p = 7; i < MazeCount; i++, j++, k += 2, p += 5)
            {
                Maze maze = new Maze();
                maze.GenerateMaze(MazeSize.Width, MazeSize.Height, (int)((Username.data[j % (Username.dataLength - 1)] + 
                                                                            Password.data[k % (Password.dataLength - 1)]) ^ 
                                                                            PrivateSalt.data[i % (PrivateSalt.dataLength - 1)]), 0);

                beginPosX = Math.Abs(beginPosX);
                beginPosY = Math.Abs(beginPosY);
                int endPosX = Math.Abs(beginPosX + (Back ? -WalkSize : WalkSize));
                int endPosY = Math.Abs(beginPosY + (Back ? -WalkSize : WalkSize));

                ArrayList list = maze.Solve(beginPosX, beginPosY, endPosX, endPosY, MazeSteps * 2);

                if (list.Count < 10)
                    throw new Exception("The Maze is too small");

                BigInteger tempCalc = new BigInteger();
                for (int s = 0; s < MazeSteps; s++)
                {
                    cCellPosition cell = list[s % list.Count] as cCellPosition;

                    int temp2 = cell.x * cell.y;
                    if (temp2 == 0)
                        continue;
                    tempCalc = equK(Username, temp2, s) ^ PrivateSalt.IntValue() ^ tempCalc;
                    this.MazeKey += tempCalc;
                    beginPosX = cell.x;
                    beginPosY = cell.y;
                }
                Back = !Back;
            }

            PatchKey(ref this._mazeKey);

            return this.MazeKey;
        }

        /// <summary>
        /// Patches the key by removing the 255 in the beginning of the key
        /// </summary>
        /// <param name="key"></param>
        private void PatchKey(ref BigInteger key)
        {
            byte[] _key = key.getBytes();
            int count = 0;
            for (int i = 0; i < _key.Length; i++, count++)
            {
                if (_key[i] != 255)
                    break;
            }

            if (count > 0)
            {
                byte[] tempKey = new byte[count];
                new Random(PrivateSalt.IntValue()).NextBytes(tempKey);
                Array.Copy(tempKey, _key, tempKey.Length);
                key = new BigInteger(_key);
            }
        }

        public WopEx GetWopEncryption()
        {
            byte[] key = MazeKey.getBytes();
            byte[] salt = PrivateSalt.getBytes();
            byte[] CryptCode = new byte[0];
            byte[] DecryptCode = new byte[0];
            WopEx.GenerateCryptoCode(BitConverter.ToInt32(key, 0) + BitConverter.ToInt32(salt, 0), 15, ref CryptCode, ref DecryptCode);
            WopEx wop = new WopEx(key, salt, CryptCode, DecryptCode, false, true);
            return wop;
        }

        public byte[] GetEncryptedPublicKey()
        {
            byte[] key = MazeKey.getBytes();
            byte[] salt = PrivateSalt.getBytes();

            //also step 7 but here we encrypt it
            byte[] publicData = new byte[this.PublicKeyData.Length];
            Array.Copy(this.PublicKeyData, publicData, publicData.Length); //copy the public key data so the original will be still in memory

            GetWopEncryption().Encrypt(publicData, 0, publicData.Length);
            return publicData;
        }

        internal void ApplyKey(WopEx wopEx, byte[] key)
        {
            for (int i = 0; i < wopEx.Key.Length + (key.Length * 3); i++)
            {
                wopEx.Key[i % wopEx.Key.Length] += key[i % key.Length];
                wopEx.Salt[i % wopEx.Salt.Length] += key[(i + 2) % key.Length];
            }
        }

        internal void ApplyKey(WopEx wopEx, BigInteger prime)
        {
            PatchKey(ref prime);
            byte[] primeKey = prime.getBytes();
            ApplyKey(wopEx, primeKey);
        }

        protected BigInteger ModKey(BigInteger Key1, BigInteger Key2)
        {
            BigInteger orgKey1 = Key1;
            Key1 += Key2;
            Key1 = equK(Key2, orgKey1, Key1.IntValue());
            return Key1 + Key2;
        }

        protected byte[] CloneByteArray(byte[] Input)
        {
            byte[] newArray = new byte[Input.Length];
            Array.Copy(Input, newArray, newArray.Length);
            return newArray;
        }

        protected byte[] TrimArray(byte[] Input, int newLength)
        {
            if (Input.Length < newLength)
                return Input;

            byte[] newArray = new byte[Input.Length];
            Array.Copy(Input, newArray, newLength);

            if (newArray.Length > newLength)
            {
                for (int i = 0, j = newLength; j < Input.Length; i++, j++)
                {
                    newArray[i % newLength] += Input[j];
                }
            }
            Array.Resize(ref newArray, newLength);
            return newArray;
        }

        public byte[] GetByteCode()
        {
            //Step 1
            return Mazing.ByteCode;
        }

        public Stream RecalculatePrivateKey(Stream PrivateKeyData)
        {
            if (!PrivateKeyData.CanSeek || !PrivateKeyData.CanWrite)
                throw new Exception("Unable to write to the stream");

            BigInteger InversedInt = 0;

            try
            {
                InversedInt = PrivateSalt.modInverse(this.Username);
            }
            catch
            {
                //no inverse could be found
                InversedInt = PrivateSalt + this.Username;
            }

            PatchKey(ref InversedInt); //patch the key to randomize the 0xFF bytes
            byte[] inverseData = InversedInt.getBytes();

            int temp = InversedInt.IntValue();

            for (int j = 0; j <= 1; j++)
            {
                for (int i = 4 * j; i < PrivateKeyData.Length; i += 8)
                {
                    byte[] tempData = new byte[4];
                    int read = 0;

                    PrivateKeyData.Position = i;
                    if ((read = PrivateKeyData.Read(tempData, 0, tempData.Length)) <= 0)
                        break;

                    int TempKey = BitConverter.ToInt32(tempData, 0) ^ temp;

                    PrivateKeyData.Position -= read;
                    PrivateKeyData.Write(BitConverter.GetBytes(TempKey), 0, read);

                    temp = TempKey;
                }
            }
            return PrivateKeyData;
        }
    }

    public enum MazeErrorCode
    {
        Success = 0,
        WrongByteCode = 1,
        Error = 2,
        UserKeyNotFound = 3,
        /// <summary>
        /// The handshake has ended successfully
        /// </summary>
        Finished = 4
    }
}