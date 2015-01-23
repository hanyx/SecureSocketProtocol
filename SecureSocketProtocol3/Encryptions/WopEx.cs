using ProtoBuf;
using SecureSocketProtocol3.Encryptions.Compiler;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol3.Encryptions
{
    /// <summary>
    /// WopEx is a more advanced form of the WopEncryption
    /// WopEx is able to generate a random encryption and decryption algorithm(s)
    /// </summary>
    public class WopEx
    {
        private const int KEY_SIZE = 2048;

        private State EncState;
        private State DecState;

        public WopEncMode EncMode { get; private set; }

        private static object Locky = new object();

        /// <summary>
        /// The initial key
        /// </summary>
        public byte[] Key { get; private set; }

        /// <summary>
        /// The initial Salt
        /// </summary>
        public byte[] Salt { get; private set; }

        public uint Rounds { get; private set; }

        private bool UseDynamicCompiler;

        /// <summary>
        /// Initialize the WopEx Encryption
        /// </summary>
        /// <param name="Key">The key to use</param>
        /// <param name="Salt">The Salt to use</param>
        /// <param name="InitialVector">The Salt to use</param>
        /// <param name="EncryptionCode">The encryption algorithm that was generated</param>
        /// <param name="DecryptionCode">The decryption algorithm that was generated</param>
        /// <param name="WopMode">The encryption mode</param>
        /// <param name="UseCompiler">Using the dynamic compiler will increase performance</param>
        public WopEx(byte[] Key, byte[] Salt, byte[] InitialVector, byte[] EncryptionCode, byte[] DecryptionCode, WopEncMode EncMode, uint Rounds, bool UseDynamicCompiler)
        {
            if (EncryptionCode.Length != DecryptionCode.Length)
                throw new Exception("Encryption and Decryption algorithms must be the same size");
            if (Key.Length < 8 || Salt.Length < 8)
                throw new Exception("The Key and Salt must atleast have a size of 8");
            if (InitialVector.Length < 32)
                throw new Exception("The Initial Vector must atleast have a size of 32");
            if (Rounds == 0)
                throw new Exception("There must be atleast 1 round");

            this.UseDynamicCompiler = UseDynamicCompiler;

            this.Key = new byte[Key.Length];
            Array.Copy(Key, this.Key, Key.Length);

            this.Salt = new byte[Salt.Length];
            Array.Copy(Salt, this.Salt, Salt.Length);

            this.Key = ExpandKey(this.Key);
            this.Salt = ExpandKey(this.Salt);

            this.Rounds = Rounds;
            this.EncMode = EncMode;
            this.EncState = new State(BytesToLongList(this.Key), BytesToLongList(this.Salt), BitConverter.ToInt32(this.Key, 0), BytesToLongList(ExpandKey(InitialVector)), false);
            this.EncState.Instructions = ReadAlgorithm(EncryptionCode);
            this.EncState.Compile();

            this.DecState = new State(BytesToLongList(this.Key), BytesToLongList(this.Salt), BitConverter.ToInt32(this.Key, 0), BytesToLongList(ExpandKey(InitialVector)), true);
            this.DecState.Instructions = ReadAlgorithm(DecryptionCode);
            this.DecState.Compile();
        }

        private static byte[] WriteInstruction(InstructionInfo Instruction)
        {
            using (PayloadWriter pw = new PayloadWriter())
            using (MemoryStream ms = new MemoryStream())
            {
                Serializer.Serialize(ms, Instruction);
                pw.WriteByte((byte)ms.Length);
                pw.WriteBytes(ms.ToArray());
                return pw.ToByteArray();
            }
        }

        private InstructionInfo[] ReadAlgorithm(byte[] Code)
        {
            List<InstructionInfo> Instructions = new List<InstructionInfo>();
            for (int i = 0; i < Code.Length; )
            {
                byte size = Code[i];
                Instructions.Add((InstructionInfo)Serializer.Deserialize(new MemoryStream(Code, i + 1, size), typeof(InstructionInfo)));
                i += size + 1;
            }
            return Instructions.ToArray();
        }

        /// <summary>
        /// A dirty way to expand a key, need to find a more clean solution
        /// </summary>
        private byte[] ExpandKey(byte[] input)
        {
            if (input.Length > KEY_SIZE)
                return input;

            int OrgLen = input.Length;
            Array.Resize(ref input, KEY_SIZE);

            FastRandom rnd = new FastRandom(BitConverter.ToInt32(input, 0));
            const int BlockSize = 124;

            for (int i = OrgLen, j = 5; i < KEY_SIZE; i += BlockSize, j += 32)
            {
                int len = i + BlockSize < KEY_SIZE ? BlockSize : KEY_SIZE - i;
                rnd.NextBytes(input, i, input.Length);
                rnd = new FastRandom(BitConverter.ToInt32(input, j));
            }

            return input;
        }

        private ulong[] BytesToLongList(byte[] Key)
        {
            List<ulong> longs = new List<ulong>();

            for (int i = 0; i < Key.Length; )
            {
                if (i + 8 < Key.Length)
                {
                    longs.Add(BitConverter.ToUInt64(Key, i));
                    i += 8;
                }
                else if (i + 4 < Key.Length)
                {
                    longs.Add(BitConverter.ToUInt32(Key, i));
                    i += 4;
                }
                else
                {
                    longs.Add(Key[i]);
                    i++;
                }
            }

            return longs.ToArray();
        }

        /// <summary>
        /// Encrypt the data
        /// </summary>
        /// <param name="Data">The data to encrypt</param>
        /// <param name="Offset">The index where the data starts</param>
        /// <param name="Length">The length to encrypt</param>
        public void Encrypt(byte[] Data, int Offset, int Length)
        {
            lock (EncState)
            {
                int OrgLen = Length;
                Length += Offset;

                for (int round = 0; round < Rounds; round++)
                {
                    ulong temp_Value = EncState.IV[EncMode == WopEncMode.Simple ? 0 : EncState.IV_Pos]; //is being used for CBC Mode (Block-Cipher-Chaining Mode)

                    using (PayloadWriter pw = new PayloadWriter(new System.IO.MemoryStream(Data)))
                    {
                        for (int i = Offset, k = 0; i < Length; k++)
                        {
                            pw.vStream.Position = i;
                            int usedsize = 0;

                            if (i + 8 < Length)
                            {
                                ulong OrgValue = BitConverter.ToUInt64(Data, i);
                                usedsize = 8;

                                ulong value = Encrypt_Core_Big(OrgValue, OrgLen, k) ^ temp_Value;
                                pw.WriteULong(value);
                                temp_Value += value;
                                EncState.Seed += (int)OrgValue;
                            }
                            else
                            {
                                byte OrgValue = Data[i];
                                usedsize = 1;

                                byte value = Encrypt_Core_Small(OrgValue, OrgLen, k);
                                pw.WriteByte(value);
                                EncState.Seed += OrgValue;
                            }

                            i += usedsize;

                            if (EncMode != WopEncMode.Simple)
                            {
                                EncState.Key_Pos += 1;
                                EncState.Salt_Pos += 1;
                            }
                        }
                    }
                }

                EncState.IV_Pos = (EncState.IV_Pos + 1) % EncState.IV.Length;

                switch (EncMode)
                {
                    case WopEncMode.GenerateNewAlgorithm:
                    {
                        InstructionInfo tempEncCode = null;
                        InstructionInfo tempDecCode = null;
                        FastRandom fastRand = new FastRandom(EncState.Seed);

                        for (int i = 0; i < EncState.Instructions.Length; i++)
                        {
                            GetNextRandomInstruction(fastRand, ref tempEncCode, ref tempDecCode);
                            EncState.Instructions[i] = tempEncCode;
                        }

                        if (UseDynamicCompiler)
                        {
                            EncState.Compile();
                        }
                        break;
                    }
                    case WopEncMode.ShuffleInstructions:
                    {
                        ShuffleInstructions(EncState.Instructions, EncState.Seed);

                        if (UseDynamicCompiler)
                        {
                            EncState.Compile();
                        }
                        break;
                    }
                }
            }
        }

        private BigInteger Encrypt_Core_BigInteger(BigInteger value, int OrgLen, int k)
        {
            if (EncMode == WopEncMode.Simple || Rounds > 1)
            {
                value ^= (ulong)(EncState.Key[(k % EncState.Key.Length)] * EncState.Salt[(OrgLen + k) % EncState.Salt.Length]);
            }
            else
            {
                value ^= (ulong)(EncState.Key[(EncState.random.Next(0, EncState.Key.Length) + EncState.Key_Pos) % EncState.Key.Length] * EncState.Salt[(OrgLen + EncState.Salt_Pos) % EncState.Salt.Length]);
            }

            for (int j = 0; j < EncState.Instructions.Length; j++)
            {
                bool isExecuted = false;
                InstructionInfo inf = inf = EncState.Instructions[j];

                BigInteger temp = ExecuteInstruction(value, inf, ref isExecuted, false);
                if (isExecuted)
                {
                    value = temp;
                }
            }
            return value;
        }

        private ulong Encrypt_Core_Big(ulong value, int OrgLen, int k)
        {
            if (EncMode == WopEncMode.Simple || Rounds > 1)
            {
                value ^= (ulong)(EncState.Key[(k % EncState.Key.Length)] * EncState.Salt[(OrgLen + k) % EncState.Salt.Length]);
            }
            else
            {
                value ^= (ulong)(EncState.Key[(EncState.random.Next(0, EncState.Key.Length) + EncState.Key_Pos) % EncState.Key.Length] * EncState.Salt[(OrgLen + EncState.Salt_Pos) % EncState.Salt.Length]);
            }

            if (UseDynamicCompiler)
            {
                value = EncState.Algorithm.CalculateULong(value);
            }
            else
            {
                for (int j = 0; j < EncState.Instructions.Length; j++)
                {
                    bool isExecuted = false;
                    InstructionInfo inf = EncState.Instructions[j];

                    ulong temp = ExecuteInstruction(value, inf, ref isExecuted, false);
                    if (isExecuted)
                    {
                        value = temp;
                    }
                }
            }
            return value;
        }

        private byte Encrypt_Core_Small(byte value, int OrgLen, int k)
        {
            if (EncMode == WopEncMode.Simple || Rounds > 1)
            {
                value ^= (byte)(EncState.Key[(k % EncState.Key.Length)] * EncState.Salt[(OrgLen + k) % EncState.Salt.Length]);
            }
            else
            {
                value ^= (byte)(EncState.Key[(EncState.random.Next(0, EncState.Key.Length) + EncState.Key_Pos) % EncState.Key.Length] * EncState.Salt[(OrgLen + EncState.Salt_Pos) % EncState.Salt.Length]);
            }

            for (int j = 0; j < EncState.Instructions.Length; j++)
            {
                bool isExecuted = false;
                InstructionInfo inf = inf = EncState.Instructions[j];

                byte temp = ExecuteInstruction(value, inf, ref isExecuted, false);
                if (isExecuted)
                {
                    value = temp;
                }
            }
            return value;
        }

        /// <summary>
        /// Decrypt the data
        /// </summary>
        /// <param name="Data">The data to decrypt</param>l
        /// <param name="Offset">The index where the data starts</param>
        /// <param name="Length">The length to decrypt</param>
        public void Decrypt(byte[] Data, int Offset, int Length)
        {
            lock (DecState)
            {
                int OrgLen = Length;
                Length += Offset;

                for (int round = 0; round < Rounds; round++)
                {
                    using (PayloadWriter pw = new PayloadWriter(new System.IO.MemoryStream(Data)))
                    {
                        ulong temp_Value = DecState.IV[EncMode == WopEncMode.Simple ? 0 : DecState.IV_Pos]; //is being used for CBC Mode (Block-Cipher-Chaining Mode)
                        for (int i = Offset, k = 0; i < Length; k++)
                        {
                            pw.vStream.Position = i;
                            int usedsize = 0;
                            ulong value = 0;
                            ulong OrgReadValue = 0;

                            if (i + 8 < Length)
                            {
                                OrgReadValue = BitConverter.ToUInt64(Data, i);
                                usedsize = 8;

                                value = Decrypt_Core_Big(OrgReadValue ^ temp_Value, OrgLen, k);
                                pw.WriteULong(value);
                            }
                            else
                            {
                                OrgReadValue = Data[i];
                                usedsize = 1;

                                value = Decrypt_Core_Small((byte)OrgReadValue, OrgLen, k);
                                pw.WriteByte((byte)value);
                            }

                            temp_Value += OrgReadValue;
                            DecState.Seed += (int)value;
                            i += usedsize;

                            if (EncMode != WopEncMode.Simple)
                            {
                                DecState.Key_Pos += 1;
                                DecState.Salt_Pos += 1;
                            }
                        }
                    }
                }

                DecState.IV_Pos = (DecState.IV_Pos + 1) % DecState.IV.Length;

                switch (EncMode)
                {
                    case WopEncMode.GenerateNewAlgorithm:
                    {
                        InstructionInfo tempEncCode = null;
                        InstructionInfo tempDecCode = null;
                        FastRandom fastRand = new FastRandom(DecState.Seed);

                        for (int i = 0; i < DecState.Instructions.Length; i++)
                        {
                            GetNextRandomInstruction(fastRand, ref tempEncCode, ref tempDecCode);
                            DecState.Instructions[i] = tempDecCode;
                        }

                        if (UseDynamicCompiler)
                        {
                            DecState.Compile();
                        }
                        break;
                    }
                    case WopEncMode.ShuffleInstructions:
                    {
                        ShuffleInstructions(DecState.Instructions, DecState.Seed);

                        if (UseDynamicCompiler)
                        {
                            DecState.Compile();
                        }
                        break;
                    }
                }
            }
        }

        private ulong Decrypt_Core_Big(ulong value, int OrgLen, int k)
        {
            if (UseDynamicCompiler)
            {
                value = DecState.Algorithm.CalculateULong(value);
            }
            else
            {
                for (int j = DecState.Instructions.Length - 1; j >= 0; j--)
                {
                    bool isExecuted = false;
                    InstructionInfo inf = DecState.Instructions[j];

                    ulong temp = ExecuteInstruction(value, inf, ref isExecuted, true);
                    if (isExecuted)
                    {
                        value = temp;
                    }
                }
            }

            if (EncMode == WopEncMode.Simple || Rounds > 1)
            {
                value ^= (ulong)(DecState.Key[(k % DecState.Key.Length)] * DecState.Salt[(OrgLen + k) % DecState.Salt.Length]);
            }
            else
            {
                value ^= (ulong)(DecState.Key[(DecState.random.Next(0, DecState.Key.Length) + DecState.Key_Pos) % DecState.Key.Length] * DecState.Salt[(OrgLen + DecState.Salt_Pos) % DecState.Salt.Length]);
            }
            return value;
        }

        private byte Decrypt_Core_Small(byte value, int OrgLen, int k)
        {
            for (int j = DecState.Instructions.Length - 1; j >= 0; j--)
            {
                bool isExecuted = false;
                InstructionInfo inf = inf = DecState.Instructions[j];

                byte temp = ExecuteInstruction(value, inf, ref isExecuted, true);
                if (isExecuted)
                {
                    value = temp;
                }
            }

            if (EncMode == WopEncMode.Simple || Rounds > 1)
            {
                value ^= (byte)(DecState.Key[(k % DecState.Key.Length)] * DecState.Salt[(OrgLen + k) % DecState.Salt.Length]);
            }
            else
            {
                value ^= (byte)(DecState.Key[(DecState.random.Next(0, DecState.Key.Length) + DecState.Key_Pos) % DecState.Key.Length] * DecState.Salt[(OrgLen + DecState.Salt_Pos) % DecState.Salt.Length]);
            }
            return value;
        }

        private byte ExecuteInstruction(byte value, InstructionInfo inf, ref bool Executed, bool IsDecrypt)
        {
            Executed = true;
            byte InstVal = inf.Value_Byte;
            switch (inf.Inst)
            {
                //case Instruction.SwapBits:
                //    return SwapBits(value);
                case Instruction.Plus:
                    return (byte)(value + InstVal);
                case Instruction.Minus:
                    return (byte)(value - InstVal);
                case Instruction.RotateLeft_Big:
                    return RotateLeft(value);
                case Instruction.RotateRight_Big:
                    return RotateRight(value);
                /*case Instruction.BitLeft:
                    return (byte)(value << 1);
                case Instruction.BitRight:
                    return (byte)(value >> 1);*/
                case Instruction.XOR:
                    return value ^= InstVal;
            }
            Executed = false;
            return 0;
        }
        private ulong ExecuteInstruction(ulong value, InstructionInfo inf, ref bool Executed, bool IsDecrypt)
        {
            Executed = true;
            switch (inf.Inst)
            {
                case Instruction.SwapBits:
                    return SwapBits(value);
                case Instruction.Plus:
                    return value + inf.Value_Long;
                case Instruction.Minus:
                    return value - inf.Value_Long;
                case Instruction.RotateLeft_Big:
                    return RotateLeft(value, (int)inf.Value_Long);
                case Instruction.RotateRight_Big:
                    return RotateRight(value, (int)inf.Value_Long);
                /*case Instruction.BitLeft:
                    return value << 1;
                case Instruction.BitRight:
                    return value >> 1;*/
                case Instruction.XOR:
                    return value ^ inf.Value_Long;
                case Instruction.ForLoop_PlusMinus:
                {
                    /* Heavy "Algorithm" */
                    /*uint decValue = inf.Value;
                    uint incValue = inf.Value2;
                    uint loops = inf.Value3 >> 1;

                    if (IsDecrypt)
                    {
                        for (int i = 0; i < loops; i++)
                        {
                            value += decValue;
                            value -= incValue;
                        }
                    }
                    else
                    {
                        for (int i = 0; i < loops; i++)
                        {
                            value -= decValue;
                            value += incValue;
                        }
                    }
                    return value;*/
                    break;
                }
            }
            Executed = false;
            return 0;
        }
        private BigInteger ExecuteInstruction(BigInteger value, InstructionInfo inf, ref bool Executed, bool IsDecrypt)
        {
            Executed = true;
            switch (inf.Inst)
            {
                //case Instruction.SwapBits:
                //    return SwapBits(value);
                case Instruction.Plus:
                    return value + inf.Value;
                case Instruction.Minus:
                    return value - inf.Value;
                /*case Instruction.RotateLeft_Big:
                    return RotateLeft(value, (int)inf.Value);
                case Instruction.RotateRight_Big:
                    return RotateRight(value, (int)inf.Value);
                case Instruction.BitLeft:
                    return value << 1;
                case Instruction.BitRight:
                    return value >> 1;*/
                case Instruction.XOR:
                    return value ^= inf.Value;
                case Instruction.ForLoop_PlusMinus:
                {
                    /* Heavy "Algorithm" */
                    /*uint decValue = inf.Value;
                    uint incValue = inf.Value2;
                    uint loops = inf.Value3 >> 1;

                    if (IsDecrypt)
                    {
                        for (int i = 0; i < loops; i++)
                        {
                            value += decValue;
                            value -= incValue;
                        }
                    }
                    else
                    {
                        for (int i = 0; i < loops; i++)
                        {
                            value -= decValue;
                            value += incValue;
                        }
                    }
                    return value;*/
                    break;
                }
            }
            Executed = false;
            return 0;
        }

        /// <summary>
        /// Generate a random encryption/decryption algorithm
        /// </summary>
        /// <param name="Instructions">The max number of instructions to generate, higher=slower</param>
        /// <param name="EncryptCode"></param>
        /// <param name="DecryptCode"></param>
        /// <param name="TestAlgorithm">Test the algorithm for strongness, it will take longer generating the algorithm</param>
        public static void GenerateCryptoCode(int Seed, int Instructions, ref byte[] EncryptCode, ref byte[] DecryptCode, bool TestAlgorithm = true)
        {
            lock (Locky)
            {
                FastRandom rnd = new FastRandom(Seed);
                do
                {
                    using (PayloadWriter EncPw = new PayloadWriter())
                    using (PayloadWriter DecPw = new PayloadWriter())
                    {
                        //generate a random instruction and when generated set the opposide for Decryption
                        for (int i = 0; i < Instructions; i++)
                        {
                            InstructionInfo EncInstruction = null;
                            InstructionInfo DecInstruction = null;
                            GetNextRandomInstruction(rnd, ref EncInstruction, ref DecInstruction);

                            EncPw.WriteBytes(WriteInstruction(EncInstruction));
                            DecPw.WriteBytes(WriteInstruction(DecInstruction));
                        }

                        EncryptCode = EncPw.ToByteArray();
                        DecryptCode = DecPw.ToByteArray();
                    }
                } while (TestAlgorithm && IsAlgorithmWeak(EncryptCode, DecryptCode, Seed));
            }
        }

        private static object RndInstLock = new object();
        private static void GetNextRandomInstruction(FastRandom rnd, ref InstructionInfo EncInstruction, ref InstructionInfo DecInstruction)
        {
            lock (RndInstLock)
            {
                Instruction[] InstructionList = new Instruction[]
                {
                    //Instruction.BitLeft, //unstable do not use
                    Instruction.Minus,
                    Instruction.Plus,
                    //Instruction.ForLoop_PlusMinus, 
                    //Instruction.RotateLeft_Big,
                    //Instruction.RotateLeft_Small,
                    Instruction.SwapBits,
                    Instruction.XOR
                };

                Instruction inst = InstructionList[rnd.Next(0, InstructionList.Length)];

                switch (inst)
                {
                    case Instruction.BitLeft:
                    {
                        int bitSize = rnd.Next(1, 3); //maybe needs to be higher ?
                        EncInstruction = new InstructionInfo(inst, bitSize);
                        DecInstruction = new InstructionInfo(Instruction.BitRight, bitSize);
                        break;
                    }
                    case Instruction.Minus:
                    {
                        byte[] TempDate = new byte[32];
                        rnd.NextBytes(TempDate);

                        EncInstruction = new InstructionInfo(inst, new BigInteger(TempDate));
                        DecInstruction = new InstructionInfo(Instruction.Plus, new BigInteger(TempDate));
                        break;
                    }
                    case Instruction.Plus:
                    {
                        byte[] TempDate = new byte[32];
                        rnd.NextBytes(TempDate);

                        EncInstruction = new InstructionInfo(inst, new BigInteger(TempDate));
                        DecInstruction = new InstructionInfo(Instruction.Minus, new BigInteger(TempDate));
                        break;
                    }
                    case Instruction.ForLoop_PlusMinus:
                    {
                        int size = rnd.Next();
                        int size2 = rnd.Next();
                        int loops = rnd.Next(2, 255);

                        EncInstruction = new InstructionInfo(inst, (uint)size, (uint)size2, loops);
                        DecInstruction = new InstructionInfo(inst, (uint)size, (uint)size2, loops);
                        break;
                    }
                    case Instruction.RotateLeft_Big:
                    {
                        byte bitSize = (byte)rnd.Next(1, 60);

                        EncInstruction = new InstructionInfo(inst, (uint)bitSize);
                        DecInstruction = new InstructionInfo(Instruction.RotateRight_Big, (uint)bitSize);
                        break;
                    }
                    case Instruction.RotateLeft_Small:
                    {
                        byte bitSize = (byte)rnd.Next(1, 30);

                        EncInstruction = new InstructionInfo(inst, (uint)bitSize);
                        DecInstruction = new InstructionInfo(Instruction.RotateRight_Small, (uint)bitSize);
                        break;
                    }
                    case Instruction.SwapBits:
                    {
                        EncInstruction = new InstructionInfo(inst, 0);
                        DecInstruction = new InstructionInfo(inst, 0);
                        break;
                    }
                    case Instruction.XOR:
                    {
                        byte[] TempDate = new byte[32];
                        rnd.NextBytes(TempDate);

                        EncInstruction = new InstructionInfo(inst, new BigInteger(TempDate));
                        DecInstruction = new InstructionInfo(inst, new BigInteger(TempDate));
                        break;
                    }
                    default: { break; }
                }
            }
        }

        /// <summary>
        /// Agressively scan the algorithm for weakness
        /// </summary>
        /// <param name="EncryptCode"></param>
        /// <param name="DecryptCode"></param>
        /// <returns></returns>
        private static bool IsAlgorithmWeak(byte[] EncryptCode, byte[] DecryptCode, int Seed)
        {
            FastRandom rnd = new FastRandom(Seed);
            byte[] RandData = new byte[513];
            rnd.NextBytes(RandData);

            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1 };
            byte[] IV = new byte[] { 100, 132, 194, 103, 165, 222, 64, 110, 144, 217, 202, 129, 54, 97, 230, 25, 34, 58, 100, 79, 80, 124, 14, 61, 191, 5, 174, 94, 194, 10, 222, 215 };

            WopEx wop = new WopEx(Key, Salt, IV, EncryptCode, DecryptCode, WopEncMode.Simple, 1, true);

            //test it 50 times if it's safe to use
            for (int x = 0; x < 50; x++)
            {
                byte[] crypted = new byte[RandData.Length];
                Array.Copy(RandData, crypted, RandData.Length);

                wop.Encrypt(crypted, 0, crypted.Length);

                double Equals = 0;

                for (int i = 0; i < crypted.Length; i++)
                {
                    if (RandData[i] == crypted[i])
                    {
                        Equals++;
                    }
                }

                wop.Decrypt(crypted, 0, crypted.Length);

                //check if decryption went successful
                if (RandData.Length != crypted.Length)
                    return true;

                for (int i = 0; i < RandData.Length; i++)
                {
                    if (RandData[i] != crypted[i])
                    {
                        //the decryption-routine failed
                        return true;
                    }
                }

                double Pertentage = (Equals / (double)RandData.Length) * 100D;
                bool isWeak = Pertentage > 5; //if >5 % is the same as original it's a weak algorithm

                if (isWeak)
                    return true;
            }
            return false;
        }

        private ushort SwapBits(ushort x)
        {
            return (ushort)((ushort)((x & 0xFF) << 8) | ((x >> 8) & 0xFF));
        }

        private uint SwapBits(uint x)
        {
            return ((x & 0x000000FF) << 24) +
                   ((x & 0x0000FF00) << 8) +
                   ((x & 0x00FF0000) >> 8) +
                   ((x & 0xFF000000) >> 24);
        }

        private ulong SwapBits(ulong value)
        {
            return ((0x00000000000000FF) & (value >> 56) |
                    (0x000000000000FF00) & (value >> 40) |
                    (0x0000000000FF0000) & (value >> 24) |
                    (0x00000000FF000000) & (value >> 8) |
                    (0x000000FF00000000) & (value << 8) |
                    (0x0000FF0000000000) & (value << 24) |
                    (0x00FF000000000000) & (value << 40) |
                    (0xFF00000000000000) & (value << 56));
        }

        private ulong RotateLeft(ulong value, int count)
        {
            return (value << count) | (value >> (64 - count));
        }

        private ulong RotateRight(ulong value, int count)
        {
            return (value >> count) | (value << (64 - count));
        }

        private uint RotateLeft(uint value, int count)
        {
            return (value << count) | (value >> (32 - count));
        }

        private uint RotateRight(uint value, int count)
        {
            return (value >> count) | (value << (32 - count));
        }

        private byte RotateRight(byte value)
        {
            return (byte)(((value & 1) << 7) | (value >> 1));
        }

        private byte RotateLeft(byte value)
        {
            return (byte)(((value & 0x80) >> 7) | (value << 1));
        }

        private void ShuffleInstructions(InstructionInfo[] insts, int Seed)
        {
            FastRandom rnd = new FastRandom(Seed);
            for (int i = insts.Length, j = 0; i > 1; i--, j++)
            {
                int pos = rnd.Next(i); // 0 <= j <= i-1
                InstructionInfo tmp = insts[pos];
                insts[pos] = insts[i - 1];
                insts[i - 1] = tmp;
            }
        }

        public enum Instruction
        {
            BitLeft = 1,
            BitRight = 2,
            RotateLeft_Big = 3,
            RotateRight_Big = 4,
            RotateLeft_Small = 5,
            RotateRight_Small = 6,
            Plus = 7,
            Minus = 8,
            SwapBits = 9,
            XOR = 10,
            ForLoop_PlusMinus = 11
        }

        private class State
        {
            public bool IsDecryptState { get; private set; }
            public InstructionInfo[] Instructions { get; set; }
            public AlgorithmCompiler AlgoCompiler { get; private set; }

            public ulong[] Key { get; private set; }
            public ulong[] Salt { get; private set; }
            public IAlgorithm Algorithm { get; private set; }

            /// <summary> Initial Vector </summary>
            public ulong[] IV { get; private set; }

            public int Seed = 0;
            public int Key_Pos = 0;
            public int Salt_Pos = 1;
            public int IV_Pos = 0;
            public FastRandom random;

            public State()
            {
                this.Instructions = new InstructionInfo[0];
                this.Key = new ulong[0];
                this.Salt = new ulong[0];
                this.IV = new ulong[0];
                this.random = new FastRandom();
            }

            public State(ulong[] key, ulong[] salt, int seed, ulong[] IV, bool IsDecryptState)
            {
                this.Instructions = new InstructionInfo[0];
                this.random = new FastRandom(seed);
                this.Seed = seed;
                this.IsDecryptState = IsDecryptState;
                AlgoCompiler = new AlgorithmCompiler(IsDecryptState);

                this.Key = new ulong[key.Length];
                Array.Copy(key, this.Key, key.Length);

                this.Salt = new ulong[salt.Length];
                Array.Copy(salt, this.Salt, salt.Length);

                this.IV = new ulong[IV.Length];
                Array.Copy(IV, this.IV, IV.Length);
            }

            public void Compile()
            {
                Algorithm = AlgoCompiler.Compile(Instructions);
            }
        }
    }
}