using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Encryptions
{
    /// <summary>
    /// WopEx is a more advanced form of the WopEncryption
    /// WopEx is able to generate a random encryption and decryption algorithm
    /// </summary>
    public class WopEx
    {
        private InstructionInfo[] _encInstructions;
        private InstructionInfo[] _decInstructions;

        public InstructionInfo[] EncInstructions { get { return _encInstructions; } }
        public InstructionInfo[] DecInstructions { get { return _decInstructions; } }

        public byte[] Key { get; private set; }
        public byte[] Salt { get; private set; }

        private int EncSeed = 0;
        private int DecSeed = 0;

        private int Enc_Key_Pos = 0;
        private int Dec_Key_Pos = 0;

        private int Enc_Salt_Pos = 1;
        private int Dec_Salt_Pos = 1;

        private Random enc_random;
        private Random dec_random;

        public WopEncMode WopMode { get; private set; }

        private static object Locky = new object();

        /// <summary>
        /// Initialize the WopEx Encryption
        /// </summary>
        /// <param name="Key">The key to use</param>
        /// <param name="Salt">The Salt to use</param>
        /// <param name="EncryptionCode">The encryption algorithm that was generated</param>
        /// <param name="DecryptionCode">The decryption algorithm that was generated</param>
        /// <param name="WopMode">The encryption mode</param>
        public WopEx(byte[] Key, byte[] Salt, byte[] EncryptionCode, byte[] DecryptionCode, WopEncMode WopMode)
        {
            if (EncryptionCode.Length != DecryptionCode.Length)
                throw new Exception("Encryption and Decryption algorithms must be the same size");
            if (Key.Length < 4 || Salt.Length < 4)
                throw new Exception("The Key and Salt must atleast have a size of 4");

            this.Key = Key;
            this.Salt = Salt;

            this.EncSeed = BitConverter.ToInt32(Key, 0);
            this.DecSeed = BitConverter.ToInt32(Key, 0);

            this.enc_random = new Random(EncSeed);
            this.dec_random = new Random(DecSeed);

            this.WopMode = WopMode;
            ReadAlgorithm(EncryptionCode, DecryptionCode, ref _encInstructions, ref _decInstructions);
        }

        private void ReadAlgorithm(byte[] EncryptionCode, byte[] DecryptionCode, ref InstructionInfo[] EncInstructions, ref InstructionInfo[] DecInstructions)
        {
            List<InstructionInfo> temp_EncInstructions = new List<InstructionInfo>();
            List<InstructionInfo> temp_DecInstructions = new List<InstructionInfo>();

            using (PayloadReader EncPr = new PayloadReader(EncryptionCode))
            using (PayloadReader DecPr = new PayloadReader(DecryptionCode))
            {
                while (EncPr.Offset < EncPr.Length)
                {
                    Instruction EncInst = (Instruction)EncPr.ReadByte();
                    Instruction DecInst = (Instruction)DecPr.ReadByte();

                    switch (EncInst)
                    {
                        case Instruction.Plus:
                        case Instruction.Minus:
                        case Instruction.XOR:
                        {
                            temp_EncInstructions.Add(new InstructionInfo(EncInst, (uint)EncPr.ReadInteger()));
                            break;
                        }
                        case Instruction.BitRight:
                        case Instruction.BitLeft:
                        case Instruction.RotateLeft_Big:
                        case Instruction.RotateLeft_Small:
                        case Instruction.RotateRight_Big:
                        case Instruction.RotateRight_Small:
                        {
                            temp_EncInstructions.Add(new InstructionInfo(EncInst, EncPr.ReadByte()));
                            break;
                        }
                        case Instruction.SwapBits:
                        {
                            temp_EncInstructions.Add(new InstructionInfo(EncInst, 0));
                            break;
                        }
                        case Instruction.ForLoop_PlusMinus:
                        {
                            temp_EncInstructions.Add(new InstructionInfo(EncInst, (uint)EncPr.ReadInteger(), (uint)EncPr.ReadInteger(), EncPr.ReadByte()));
                            break;
                        }
                        default:
                        {
                            throw new Exception("Unknown instruction " + EncInst);
                        }
                    }

                    switch (DecInst)
                    {
                        case Instruction.Plus:
                        case Instruction.Minus:
                        case Instruction.XOR:
                        {
                            temp_DecInstructions.Add(new InstructionInfo(DecInst, (uint)DecPr.ReadInteger()));
                            break;
                        }
                        case Instruction.BitRight:
                        case Instruction.BitLeft:
                        case Instruction.RotateLeft_Big:
                        case Instruction.RotateLeft_Small:
                        case Instruction.RotateRight_Big:
                        case Instruction.RotateRight_Small:
                        {
                            temp_DecInstructions.Add(new InstructionInfo(DecInst, DecPr.ReadByte()));
                            break;
                        }
                        case Instruction.SwapBits:
                        {
                            temp_DecInstructions.Add(new InstructionInfo(DecInst, 0));
                            break;
                        }
                        case Instruction.ForLoop_PlusMinus:
                        {
                            temp_DecInstructions.Add(new InstructionInfo(EncInst, (uint)DecPr.ReadInteger(), (uint)DecPr.ReadInteger(), DecPr.ReadByte()));
                            break;
                        }
                        default:
                        {
                            throw new Exception("Unknown instruction " + DecInst);
                        }
                    }
                }
            }
            EncInstructions = temp_EncInstructions.ToArray();
            DecInstructions = temp_DecInstructions.ToArray();
        }

        /// <summary>
        /// Encrypt the data
        /// </summary>
        /// <param name="Data">The data to encrypt</param>
        /// <param name="Offset">The index where the data starts</param>
        /// <param name="Length">The length to encrypt</param>
        public void Encrypt(byte[] Data, int Offset, int Length)
        {
            lock (EncInstructions)
            {
                int OrgLen = Length;
                Length += Offset;

                uint tempCrypt = 0;

                using (PayloadWriter pw = new PayloadWriter(new System.IO.MemoryStream(Data)))
                {
                    for (int i = Offset, k = 0; i < Length; k++)
                    {
                        pw.vStream.Position = i;
                        int size = i + 4 < Length ? 4 : Length - i;
                        int usedsize = 0;
                        uint value = 0;

                        if (size == 4)
                        {
                            value = BitConverter.ToUInt32(Data, i);
                            usedsize = 4;
                        }
                        else
                        {
                            value = Data[i];
                            usedsize = 1;
                        }

                        bool isExecuted = false;
                        int InstructionsExecuted = 0;

                        this.EncSeed += (int)value;

                        if (usedsize == 4)
                        {
                            if(WopMode == WopEncMode.Simple)
                            {
                                value ^= (uint)(Key[(k % Key.Length)] * Salt[(OrgLen + k) % Salt.Length]);
                            }
                            else
                            {
                                value ^= (uint)(Key[(enc_random.Next(0, Key.Length) + Enc_Key_Pos) % Key.Length] * Salt[(OrgLen + Enc_Salt_Pos) % Salt.Length]);
                            }

                            for (int j = 0; j < EncInstructions.Length; j++)
                            {
                                InstructionInfo inf = EncInstructions[j];
                                uint temp = ExecuteInstruction(value, inf, ref isExecuted, false);
                                if (isExecuted)
                                {
                                    value = temp;
                                    InstructionsExecuted++;
                                }
                            }
                            pw.WriteUInteger(value);
                        }
                        else
                        {
                            if (WopMode == WopEncMode.Simple)
                            {
                                value ^= (byte)(Key[(k % Key.Length)] * Salt[(OrgLen + k) % Salt.Length]);
                            }
                            else
                            {
                                value ^= (byte)(Key[(enc_random.Next(0, Key.Length) + Enc_Key_Pos) % Key.Length] * Salt[(OrgLen + Enc_Salt_Pos) % Salt.Length]);
                            }

                            for (int j = 0; j < EncInstructions.Length; j++)
                            {
                                InstructionInfo inf = EncInstructions[j];
                                byte temp = ExecuteInstruction((byte)value, inf, ref isExecuted, false);
                                if (isExecuted)
                                {
                                    value = temp;
                                }
                            }
                            pw.WriteByte((byte)value);
                        }
                        i += usedsize;

                        if (WopMode != WopEncMode.Simple)
                        {
                            Enc_Key_Pos += 1;
                            Enc_Salt_Pos += 1;
                        }
                    }

                    switch (WopMode)
                    {
                        case WopEncMode.GenerateNewAlgorithm:
                        {
                            byte[] tempEncCode = new byte[0];
                            byte[] tempDecCode = new byte[0];
                            GenerateCryptoCode(EncSeed, this.EncInstructions.Length, ref tempEncCode, ref tempDecCode, false); //don't test, it will break
                            InstructionInfo[] encInstructions = new InstructionInfo[0];
                            InstructionInfo[] decInstructions = new InstructionInfo[0];
                            ReadAlgorithm(tempEncCode, tempDecCode, ref encInstructions, ref decInstructions);
                            this._encInstructions = encInstructions;
                            break;
                        }
                        case WopEncMode.ShuffleInstructions:
                        {
                            ShuffleInstructions(EncInstructions, EncSeed);
                            break;
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Decrypt the data
        /// </summary>
        /// <param name="Data">The data to decrypt</param>
        /// <param name="Offset">The index where the data starts</param>
        /// <param name="Length">The length to decrypt</param>
        public void Decrypt(byte[] Data, int Offset, int Length)
        {
            lock (DecInstructions)
            {
                int OrgLen = Length;
                Length += Offset;
                using (PayloadWriter pw = new PayloadWriter(new System.IO.MemoryStream(Data)))
                {
                    for (int i = Offset, k = 0; i < Length; k++)
                    {
                        pw.vStream.Position = i;
                        int size = i + 4 < Length ? 4 : Length - i;
                        int usedsize = 0;
                        uint value = 0;

                        if (size == 4)
                        {
                            value = BitConverter.ToUInt32(Data, i);
                            usedsize = 4;
                        }
                        else
                        {
                            value = Data[i];
                            usedsize = 1;
                        }

                        bool isExecuted = false;
                        int InstructionsExecuted = 0;

                        if (usedsize == 4)
                        {
                            for (int j = DecInstructions.Length - 1; j >= 0; j--)
                            {
                                InstructionInfo inf = DecInstructions[j];
                                uint temp = ExecuteInstruction(value, inf, ref isExecuted, true);
                                if (isExecuted)
                                {
                                    value = temp;
                                    InstructionsExecuted++;
                                }
                            }

                            if (WopMode == WopEncMode.Simple)
                            {
                                value ^= (uint)(Key[(k % Key.Length)] * Salt[(OrgLen + k) % Salt.Length]);
                            }
                            else
                            {
                                value ^= (uint)(Key[(dec_random.Next(0, Key.Length) + Dec_Key_Pos) % Key.Length] * Salt[(OrgLen + Dec_Salt_Pos) % Salt.Length]);
                            }

                            pw.WriteUInteger(value);
                        }
                        else
                        {
                            for (int j = DecInstructions.Length - 1; j >= 0; j--)
                            {
                                InstructionInfo inf = DecInstructions[j];
                                byte temp = ExecuteInstruction((byte)value, inf, ref isExecuted, true);
                                if (isExecuted)
                                {
                                    value = temp;
                                    InstructionsExecuted++;
                                }
                            }

                            if (WopMode == WopEncMode.Simple)
                            {
                                value ^= (byte)(Key[(k % Key.Length)] * Salt[(OrgLen + k) % Salt.Length]);
                            }
                            else
                            {
                                value ^= (byte)(Key[(dec_random.Next(0, Key.Length) + Dec_Key_Pos) % Key.Length] * Salt[(OrgLen + Dec_Salt_Pos) % Salt.Length]);
                            }

                            pw.WriteByte((byte)value);
                        }

                        this.DecSeed += (int)value;
                        i += usedsize;

                        if (WopMode != WopEncMode.Simple)
                        {
                            Dec_Key_Pos += 1;
                            Dec_Salt_Pos += 1;
                        }
                    }

                    switch (WopMode)
                    {
                        case WopEncMode.GenerateNewAlgorithm:
                        {
                            byte[] tempEncCode = new byte[0];
                            byte[] tempDecCode = new byte[0];
                            GenerateCryptoCode(DecSeed, this.EncInstructions.Length, ref tempEncCode, ref tempDecCode, false); //don't test, it will break
                            InstructionInfo[] encInstructions = new InstructionInfo[0];
                            InstructionInfo[] decInstructions = new InstructionInfo[0];
                            ReadAlgorithm(tempEncCode, tempDecCode, ref encInstructions, ref decInstructions);
                            this._decInstructions = decInstructions;
                            break;
                        }
                        case WopEncMode.ShuffleInstructions:
                        {
                            ShuffleInstructions(DecInstructions, DecSeed);
                            break;
                        }
                    }
                }
            }
        }

        private byte ExecuteInstruction(byte value, InstructionInfo inf, ref bool Executed, bool IsDecrypt)
        {
            Executed = true;
            byte InstVal = (byte)(inf.Value % 255);
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
        private uint ExecuteInstruction(uint value, InstructionInfo inf, ref bool Executed, bool IsDecrypt)
        {
            Executed = true;
            switch (inf.Inst)
            {
                case Instruction.SwapBits:
                    return SwapBits(value);
                case Instruction.Plus:
                    return value + inf.Value;
                case Instruction.Minus:
                    return value - inf.Value;
                case Instruction.RotateLeft_Big:
                    return RotateLeft(value, (int)inf.Value);
                case Instruction.RotateRight_Big:
                    return RotateRight(value, (int)inf.Value);
                /*case Instruction.BitLeft:
                    return value << 1;
                case Instruction.BitRight:
                    return value >> 1;*/
                case Instruction.XOR:
                    return value ^= inf.Value;
                case Instruction.ForLoop_PlusMinus:
                {
                    /* Some heavier algorithm, hopefully no real performance drop */
                    uint decValue = inf.Value;
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
                    return value;
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
                Random rnd = new Random(Seed);
                do
                {
                    int Insts = Instructions;
                    PayloadWriter EncPw = new PayloadWriter();
                    PayloadWriter DecPw = new PayloadWriter();

                    //generate a random instruction and when generated set the opposide for Decryption
                    while (Insts > 0)
                    {
                        Instruction inst = (Instruction)rnd.Next(0, 12);

                        switch (inst)
                        {
                            case Instruction.BitLeft:
                            {
                                byte bitSize = (byte)rnd.Next(1, 3); //maybe needs to be higher ?
                                EncPw.WriteBytes(new byte[] { (byte)inst, bitSize });
                                DecPw.WriteBytes(new byte[] { (byte)Instruction.BitRight, bitSize });
                                Insts--;
                                break;
                            }
                            case Instruction.Minus:
                            {
                                int size = rnd.Next();

                                EncPw.WriteByte((byte)inst);
                                EncPw.WriteInteger(size);

                                DecPw.WriteByte((byte)Instruction.Plus);
                                DecPw.WriteInteger(size);
                                Insts--;
                                break;
                            }
                            case Instruction.Plus:
                            {
                                int size = rnd.Next();

                                EncPw.WriteByte((byte)inst);
                                EncPw.WriteInteger(size);

                                DecPw.WriteByte((byte)Instruction.Minus);
                                DecPw.WriteInteger(size);
                                Insts--;
                                break;
                            }
                            case Instruction.ForLoop_PlusMinus:
                            {
                                int size = rnd.Next();
                                int size2 = rnd.Next();
                                int loops = rnd.Next(2, 255);

                                EncPw.WriteByte((byte)inst);
                                EncPw.WriteInteger(size);
                                EncPw.WriteInteger(size2);
                                EncPw.WriteByte((byte)loops);

                                DecPw.WriteByte((byte)Instruction.ForLoop_PlusMinus);
                                DecPw.WriteInteger(size);
                                DecPw.WriteInteger(size2);
                                DecPw.WriteByte((byte)loops);
                                Insts--;
                                break;
                            }
                            case Instruction.RotateLeft_Big:
                            {
                                byte bitSize = (byte)rnd.Next(1, 60);
                                EncPw.WriteBytes(new byte[] { (byte)inst, bitSize });
                                DecPw.WriteBytes(new byte[] { (byte)Instruction.RotateRight_Big, bitSize });
                                Insts--;
                                break;
                            }
                            case Instruction.RotateLeft_Small:
                            {
                                byte bitSize = (byte)rnd.Next(1, 15);
                                EncPw.WriteBytes(new byte[] { (byte)inst, bitSize });
                                DecPw.WriteBytes(new byte[] { (byte)Instruction.RotateRight_Small, bitSize });
                                Insts--;
                                break;
                            }
                            case Instruction.SwapBits:
                            {
                                EncPw.WriteBytes(new byte[] { (byte)inst });
                                DecPw.WriteBytes(new byte[] { (byte)inst });
                                Insts--;
                                break;
                            }
                            case Instruction.XOR:
                            {
                                int size = rnd.Next(100, int.MaxValue);

                                EncPw.WriteByte((byte)inst);
                                EncPw.WriteInteger(size);

                                DecPw.WriteByte((byte)Instruction.XOR);
                                DecPw.WriteInteger(size);
                                Insts--;
                                break;
                            }
                        }
                    }

                    EncryptCode = EncPw.ToByteArray();
                    DecryptCode = DecPw.ToByteArray();
                } while (TestAlgorithm && IsAlgorithmWeak(EncryptCode, DecryptCode, Seed));
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
            Random rnd = new Random(Seed);
            byte[] RandData = new byte[513];
            rnd.NextBytes(RandData);

            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1  };

            WopEx wop = new WopEx(Key, Salt, EncryptCode, DecryptCode, WopEncMode.Simple);

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

        public unsafe void SwapX2(Byte[] Source, int Offset, int Length)
        {
            fixed (Byte* pSource = &Source[Offset])
            {
                Byte* bp = pSource;
                Byte* bp_stop = bp + Length;

                while (bp < bp_stop)
                {
                    *(UInt16*)bp = (UInt16)(*bp << 8 | *(bp + 1));
                    bp += 2;
                }
            }
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
            Random rnd = new Random(Seed);
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

        public enum Filter
        {
            BitLeft = 1,
            RotateLeft_Big = 2,
            RotateLeft_Small = 4,
            Plus = 8,
            Minus = 16,
            SwapBits = 32,
            XOR = 64,
        }

        public class InstructionInfo
        {
            public Instruction Inst { get; private set; }
            public uint Value { get; private set; }
            public uint Value2 { get; private set; }
            public uint Value3 { get; private set; }

            public InstructionInfo(Instruction Inst, uint Value)
            {
                this.Inst = Inst;
                this.Value = Value;
            }
            public InstructionInfo(Instruction Inst, uint Value, uint Value2)
            {
                this.Inst = Inst;
                this.Value = Value;
                this.Value2 = Value2;
            }
            public InstructionInfo(Instruction Inst, uint Value, uint Value2, uint Value3)
            {
                this.Inst = Inst;
                this.Value = Value;
                this.Value2 = Value2;
                this.Value3 = Value3;
            }

            public override string ToString()
            {
                return "Instruction:" + Inst + ", Value:" + Value;
            }
        }
    }
}