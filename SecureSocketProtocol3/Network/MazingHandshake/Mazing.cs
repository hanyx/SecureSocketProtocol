using SecureSocketProtocol3.Utils;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
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

        public int Step { get; protected set; }
        public abstract bool onReceiveData(byte[] Data);
        public Size MazeSize { get; private set; }
        public int MazeCount { get; private set; }
        public int MazeSteps { get; private set; }

        private BigInteger PrivateSalt = new BigInteger();
        private BigInteger Username = new BigInteger();
        private BigInteger Password = new BigInteger();

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
            for (int i = 0; i < PrivateData.Length; i++)
            {
                bigInt += temp >> 8;
                temp += equK(bigInt, temp + (int)PrivateData[i], seed);
                bigInt += temp;
            }

            return bigInt;
        }

        public void SetLoginData(string Username, string Password, List<byte[]> PrivateKeyData, byte[] PublicKeyData)
        {
            SHA512 hasher = SHA512Managed.Create();

            for (int i = 0; i < PrivateKeyData.Count; i++)
            {
                if (PrivateKeyData[i].Length < 128)
                    throw new Exception("The Private Key must contain atleast 128 bytes");

                byte[] privHash = hasher.ComputeHash(PrivateKeyData[i], 0, 100);
                int privHashNr_1 = BitConverter.ToInt32(privHash, 26);
                int privHashNr_2 = BitConverter.ToInt32(privHash, 32);
                PrivateSalt = cubicEqu(PrivateKeyData.Count, PrivateKeyToSalt(PrivateKeyData[i]), privHashNr_1, privHashNr_1, privHashNr_2, PrivateSalt);
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

        public BigInteger GetMazeKey()
        {
            bool Back = false;
            int beginPosX = equK(Username, (BigInteger)Username.IntValue(), PrivateSalt.IntValue()).IntValue() % 50;
            int beginPosY = equK(Password, (BigInteger)Username.IntValue(), PrivateSalt.IntValue()).IntValue() & 70;

            BigInteger Key = new BigInteger();

            for (int i = 0, j = 1, k = 3, p = 7; i < MazeCount; i++, j++, k += 2, p += 5)
            {
                Maze maze = new Maze();
                maze.GenerateMaze(MazeSize.Width, MazeSize.Height, (int)((Username.data[j % (Username.dataLength - 1)] + Password.data[k % (Password.dataLength - 1)]) ^ PrivateSalt.data[p % (PrivateSalt.dataLength - 1)]), 0);

                ArrayList list = maze.Solve(Math.Abs(beginPosX), Math.Abs(beginPosY), Math.Abs(beginPosX + (Back ? -p : p)), Math.Abs(beginPosY + (Back ? -k : k)));

                BigInteger tempCalc = new BigInteger();
                for (int s = 0; s < MazeSteps; s++)
                {
                    cCellPosition cell = list[(beginPosX + beginPosY + s) % list.Count] as cCellPosition;

                    int temp2 = cell.x * cell.y;
                    tempCalc = equK(Username, temp2, s) ^ PrivateSalt.IntValue() ^ tempCalc;
                    Key += tempCalc;
                }
                beginPosX += MazeSteps;
                beginPosY += MazeSteps;
            }

            return Key;
        }
    }
}