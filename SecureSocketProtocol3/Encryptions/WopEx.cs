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
        public const int INSTRUCTION_SMALL_SIZE = 2;
        public const int INSTRUCTION_BIG_SIZE = 9;

        public InstructionInfo[] EncInstructions { get; private set; }
        public InstructionInfo[] DecInstructions { get; private set; }

        public byte[] Key { get; private set; }
        public byte[] Salt { get; private set; }

        private int EncSeed = 0;
        private int DecSeed = 0;
        private bool shuffleInsts { get; set; }

        /// <summary>
        /// Initialize the WopEx Encryption
        /// </summary>
        /// <param name="Key">The key to use</param>
        /// <param name="Salt">The Salt to use</param>
        /// <param name="EncryptionCode">The encryption algorithm that was generated</param>
        /// <param name="DecryptionCode">The decryption algorithm that was generated</param>
        /// <param name="ShuffleInstructions">Should the instructions shuffle when the encryption and decryption routines end? improves security</param>
        public WopEx(byte[] Key, byte[] Salt, byte[] EncryptionCode, byte[] DecryptionCode, bool ShuffleInstructions)
        {
            if (EncryptionCode.Length != DecryptionCode.Length)
                throw new Exception("Encryption and Decryption algorithms must be the same size");
            if (Key.Length < 4 || Salt.Length < 4)
                throw new Exception("The Key and Salt must atleast have a size of 4");

            this.EncSeed = BitConverter.ToInt32(Key, 0);
            this.DecSeed = BitConverter.ToInt32(Key, 0);

            this.shuffleInsts = ShuffleInstructions;
            List<InstructionInfo> EncInstructions = new List<InstructionInfo>();
            List<InstructionInfo> DecInstructions = new List<InstructionInfo>();

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
                            EncInstructions.Add(new InstructionInfo(EncInst, (uint)EncPr.ReadInteger()));
                            break;
                        }
                        case Instruction.BitRight:
                        case Instruction.BitLeft:
                        case Instruction.RotateLeft_Big:
                        case Instruction.RotateLeft_Small:
                        case Instruction.RotateRight_Big:
                        case Instruction.RotateRight_Small:
                        {
                            EncInstructions.Add(new InstructionInfo(EncInst, EncPr.ReadByte()));
                            break;
                        }
                        case Instruction.SwapBits:
                        {
                            EncInstructions.Add(new InstructionInfo(EncInst, 0));
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
                            DecInstructions.Add(new InstructionInfo(DecInst, (uint)DecPr.ReadInteger()));
                            break;
                        }
                        case Instruction.BitRight:
                        case Instruction.BitLeft:
                        case Instruction.RotateLeft_Big:
                        case Instruction.RotateLeft_Small:
                        case Instruction.RotateRight_Big:
                        case Instruction.RotateRight_Small:
                        {
                            DecInstructions.Add(new InstructionInfo(DecInst, DecPr.ReadByte()));
                            break;
                        }
                        case Instruction.SwapBits:
                        {
                            DecInstructions.Add(new InstructionInfo(DecInst, 0));
                            break;
                        }
                        default:
                        {
                            throw new Exception("Unknown instruction " + DecInst);
                        }
                    }
                }
            }
            this.EncInstructions = EncInstructions.ToArray();
            this.DecInstructions = DecInstructions.ToArray();
        }

        public byte[] Encrypt(byte[] Data, int Offset, int Length)
        {
            using (PayloadWriter pw = new PayloadWriter())
            {
                for (int i = Offset; i < Length; )
                {
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
                        for (int j = 0; j < EncInstructions.Length; j++)
                        {
                            InstructionInfo inf = EncInstructions[j];
                            uint temp = ExecuteInstruction(value, inf, ref isExecuted);
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
                        for (int j = 0; j < EncInstructions.Length; j++)
                        {
                            InstructionInfo inf = EncInstructions[j];
                            byte temp = ExecuteInstruction((byte)value, inf, ref isExecuted);
                            if (isExecuted)
                            {
                                value = temp;
                            }
                        }
                        pw.WriteByte((byte)value);
                    }
                    i += usedsize;
                }

                if (shuffleInsts)
                {
                    ShuffleInstructions(EncInstructions, EncSeed);
                }
                return pw.ToByteArray();
            }
        }

        public byte[] Decrypt(byte[] Data, int Offset, int Length)
        {
            using (PayloadWriter pw = new PayloadWriter())
            {
                for (int i = Offset; i < Length; )
                {
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
                            uint temp = ExecuteInstruction(value, inf, ref isExecuted);
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
                        for (int j = DecInstructions.Length - 1; j >= 0; j--)
                        {
                            InstructionInfo inf = DecInstructions[j];
                            byte temp = ExecuteInstruction((byte)value, inf, ref isExecuted);
                            if (isExecuted)
                            {
                                value = temp;
                                InstructionsExecuted++;
                            }
                        }
                        pw.WriteByte((byte)value);
                    }
                    this.DecSeed += (int)value;
                    i += usedsize;
                }

                if (shuffleInsts)
                {
                    ShuffleInstructions(DecInstructions, DecSeed);
                }
                return pw.ToByteArray();
            }
        }

        private byte ExecuteInstruction(byte value, InstructionInfo inf, ref bool Executed)
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
        private uint ExecuteInstruction(uint value, InstructionInfo inf, ref bool Executed)
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
        public static void GenerateCryptoCode(int Seed, int Instructions, ref byte[] EncryptCode, ref byte[] DecryptCode)
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
                    Instruction inst = (Instruction)rnd.Next(0, 11);

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
            } while(IsAlgorithmWeak(EncryptCode, DecryptCode));
            
        }

        /// <summary>
        /// Agressively scan the algorithm for weakness
        /// </summary>
        /// <param name="EncryptCode"></param>
        /// <param name="DecryptCode"></param>
        /// <returns></returns>
        private static bool IsAlgorithmWeak(byte[] EncryptCode, byte[] DecryptCode)
        {
            Random rnd = new Random();
            byte[] RandData = new byte[512];
            rnd.NextBytes(RandData);

            byte[] Key = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };
            byte[] Salt = new byte[] { 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5 };

            WopEx wop = new WopEx(Key, Salt, EncryptCode, DecryptCode, false);

            //test it 50 times if it's safe to use
            for (int x = 0; x < 50; x++)
            {
                byte[] Encrypted = wop.Encrypt(RandData, 0, RandData.Length);
                byte[] Decrypted = wop.Decrypt(Encrypted, 0, Encrypted.Length);
                double Equals = 0;

                for (int i = 0; i < Encrypted.Length; i++)
                {
                    if (RandData[i] == Encrypted[i])
                    {
                        Equals++;
                    }
                }

                //check if decryption went successful
                if (RandData.Length != Decrypted.Length)
                    return true;

                for (int i = 0; i < RandData.Length; i++)
                {
                    if (RandData[i] != Decrypted[i])
                    {
                        return true;
                    }
                }

                double Pertentage = (Equals / (double)RandData.Length) * 100D;
                bool isWeak = Pertentage > 5; //if >5 % is the same as original it's a weak algorithm

                return isWeak;
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

            public InstructionInfo(Instruction Inst, uint Value)
            {
                this.Inst = Inst;
                this.Value = Value;
            }

            public override string ToString()
            {
                return "Instruction:" + Inst + ", Value:" + Value;
            }
        }
    }
}