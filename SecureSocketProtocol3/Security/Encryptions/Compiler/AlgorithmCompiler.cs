using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;

namespace SecureSocketProtocol3.Security.Encryptions.Compiler
{
    /// <summary>
    /// This Algorithm Compiler is mainly used for WopEx
    /// </summary>
    internal class AlgorithmCompiler : IDisposable
    {
        private static object GlobalLock = new object();
        private static ulong GlobalInitialized = 0;
        private static ulong CompiledClasses = 0;

        private static ModuleBuilder modBuilder;
        private static TypeBuilder typeBuilder;
        private static AssemblyName assemblyName;
        private static AssemblyBuilder asmBuilder;

        public bool IsDecryptState { get; private set; }

        /// <summary>
        /// The compiled algorithm
        /// </summary>
        public IAlgorithm Algorithm { get; private set; }

        public AlgorithmCompiler(bool IsDecryptState)
        {
            this.IsDecryptState = IsDecryptState;

            lock (GlobalLock)
            {
                if(assemblyName == null)
                {
                    assemblyName = new AssemblyName();
                    assemblyName.Name = "__AlgorithmCompiler__" + GlobalInitialized++;
                    asmBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
                    modBuilder = asmBuilder.DefineDynamicModule(asmBuilder.GetName().Name);
                }
            }
        }

        public IAlgorithm Compile(InstructionInfo[] Instructions)
        {
            lock (GlobalLock)
            {
                Stopwatch sw = Stopwatch.StartNew();
                typeBuilder = modBuilder.DefineType("AlgoClass_" + CompiledClasses, TypeAttributes.Public |
                                                                 TypeAttributes.Class |
                                                                 TypeAttributes.AutoClass |
                                                                 TypeAttributes.AnsiClass |
                                                                 TypeAttributes.BeforeFieldInit |
                                                                 TypeAttributes.AutoLayout,
                                                                 typeof(object),
                                                                 new Type[] { typeof(IAlgorithm) });

                CreateConstructor(typeBuilder);
                CreateDeconstructor(typeBuilder);
                CreateUlongMethod(typeBuilder, Instructions);
                //CreateByteMethod(typeBuilder);

                Type InitType = typeBuilder.CreateType();
                Algorithm = (IAlgorithm)InitType.GetConstructor(new Type[] {  }).Invoke(new object[] {  });

                //asmBuilder.Save("Dderp.dll");
                //ulong test = Algorithm.CalculateULong(1);

                CompiledClasses++;
                sw.Stop();
                return Algorithm;
            }
        }

        private ConstructorBuilder CreateConstructor(TypeBuilder typeBuilder)
        {
            ConstructorBuilder constructor = typeBuilder.DefineConstructor(MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, CallingConventions.Standard, new Type[] { });
            ConstructorInfo conObj = typeof(object).GetConstructor(new Type[0]);
            ILGenerator il = constructor.GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Call, conObj);
            il.Emit(OpCodes.Ret);
            return constructor;
        }

        private void CreateDeconstructor(TypeBuilder typeBuilder)
        {
            MethodBuilder mb = typeBuilder.DefineMethod("Finalize", MethodAttributes.Private, Type.GetType("System.Void"), new Type[0]);
            ILGenerator gen = mb.GetILGenerator();
            gen.Emit(OpCodes.Pop);
            gen.Emit(OpCodes.Call);
            gen.Emit(OpCodes.Ret);
        }

        private void CreateUlongMethod(TypeBuilder typeBuilder, InstructionInfo[] instructions)
        {
            MethodBuilder mb = typeBuilder.DefineMethod("CalculateULong", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.NewSlot | MethodAttributes.Virtual | MethodAttributes.Final, typeof(ulong), new Type[] { typeof(ulong) });
            ILGenerator gen = mb.GetILGenerator();


            if (IsDecryptState)
            {
                for (int i = instructions.Length - 1; i >= 0; i--)
                {
                    ProcessUlongInstruction(instructions[i], gen);
                }
            }
            else
            {
                for (int i = 0; i < instructions.Length; i++)
                {
                    ProcessUlongInstruction(instructions[i], gen);
                }
            }

            gen.Emit(OpCodes.Ldarg_1);
            gen.Emit(OpCodes.Ret);

            MethodInfo CalculateULongMethod = typeof(IAlgorithm).GetMethod("CalculateULong");
            typeBuilder.DefineMethodOverride(mb, CalculateULongMethod);
        }

        private void ProcessUlongInstruction(InstructionInfo inst, ILGenerator gen)
        {
            switch (inst.Inst)
            {
                case WopEx.Instruction.Plus:
                {
                    gen.Emit(OpCodes.Ldarg_1);
                    gen.Emit(OpCodes.Ldc_I8, (long)inst.Value_Long);
                    gen.Emit(OpCodes.Add);
                    gen.Emit(OpCodes.Starg_S, 1);
                    break;
                }
                case WopEx.Instruction.Minus:
                {
                    gen.Emit(OpCodes.Ldarg_1);
                    gen.Emit(OpCodes.Ldc_I8, (long)inst.Value_Long);
                    gen.Emit(OpCodes.Sub);
                    gen.Emit(OpCodes.Starg_S, 1);
                    break;
                }
                case WopEx.Instruction.BitLeft:
                {
                    byte ShiftLeftVal = (byte)inst.Value_Long;

                    gen.Emit(OpCodes.Ldarg_1);

                    //might improve performance if we check the number
                    if (ShiftLeftVal == 0)
                        gen.Emit(OpCodes.Ldc_I4_0);
                    else if (ShiftLeftVal == 1)
                        gen.Emit(OpCodes.Ldc_I4_1);
                    else if (ShiftLeftVal == 2)
                        gen.Emit(OpCodes.Ldc_I4_2);
                    else if (ShiftLeftVal == 3)
                        gen.Emit(OpCodes.Ldc_I4_3);
                    else if (ShiftLeftVal == 4)
                        gen.Emit(OpCodes.Ldc_I4_4);
                    else if (ShiftLeftVal == 5)
                        gen.Emit(OpCodes.Ldc_I4_5);
                    else if (ShiftLeftVal == 6)
                        gen.Emit(OpCodes.Ldc_I4_6);
                    else if (ShiftLeftVal == 7)
                        gen.Emit(OpCodes.Ldc_I4_7);
                    else if (ShiftLeftVal == 8)
                        gen.Emit(OpCodes.Ldc_I4_8);
                    else
                        gen.Emit(OpCodes.Ldc_I4_S, ShiftLeftVal);

                    gen.Emit(OpCodes.Shl);
                    gen.Emit(OpCodes.Starg_S, 1);
                    break;
                }
                case WopEx.Instruction.BitRight:
                {
                    byte ShiftRightVal = (byte)inst.Value_Long;

                    gen.Emit(OpCodes.Ldarg_1);

                    //might improve performance if we check the number
                    if (ShiftRightVal == 0)
                        gen.Emit(OpCodes.Ldc_I4_0);
                    else if (ShiftRightVal == 1)
                        gen.Emit(OpCodes.Ldc_I4_1);
                    else if (ShiftRightVal == 2)
                        gen.Emit(OpCodes.Ldc_I4_2);
                    else if (ShiftRightVal == 3)
                        gen.Emit(OpCodes.Ldc_I4_3);
                    else if (ShiftRightVal == 4)
                        gen.Emit(OpCodes.Ldc_I4_4);
                    else if (ShiftRightVal == 5)
                        gen.Emit(OpCodes.Ldc_I4_5);
                    else if (ShiftRightVal == 6)
                        gen.Emit(OpCodes.Ldc_I4_6);
                    else if (ShiftRightVal == 7)
                        gen.Emit(OpCodes.Ldc_I4_7);
                    else if (ShiftRightVal == 8)
                        gen.Emit(OpCodes.Ldc_I4_8);
                    else
                        gen.Emit(OpCodes.Ldc_I4_S, ShiftRightVal);

                    gen.Emit(OpCodes.Shr_Un);
                    gen.Emit(OpCodes.Starg_S, 1);
                    break;
                }
                case WopEx.Instruction.XOR:
                {
                    gen.Emit(OpCodes.Ldarg_1);
                    gen.Emit(OpCodes.Ldc_I8, (long)inst.Value_Long);
                    gen.Emit(OpCodes.Xor);
                    gen.Emit(OpCodes.Starg_S, 1);

                    break;
                }
                case WopEx.Instruction.SwapBits:
                {
                    //this could be more optimized, but let's just keep it so it runs

                    unchecked
                    {
                        //(0x00000000000000FF) & (value >> 56)
                        gen.Emit(OpCodes.Ldc_I4, (int)0x00000000000000FF);
                        gen.Emit(OpCodes.Conv_I8);
                        gen.Emit(OpCodes.Ldarg_1);
                        gen.Emit(OpCodes.Ldc_I4_S, (byte)56); // >> 56
                        gen.Emit(OpCodes.Shr_Un);
                        gen.Emit(OpCodes.And);

                        //(0x000000000000FF00) & (value >> 40) |
                        gen.Emit(OpCodes.Ldc_I4, (int)0x000000000000FF00);
                        gen.Emit(OpCodes.Conv_I8);
                        gen.Emit(OpCodes.Ldarg_1);
                        gen.Emit(OpCodes.Ldc_I4_S, (byte)40); // >> 40
                        gen.Emit(OpCodes.Shr_Un);
                        gen.Emit(OpCodes.And);
                        gen.Emit(OpCodes.Or);

                        //(0x0000000000FF0000) & (value >> 24) |
                        gen.Emit(OpCodes.Ldc_I4, (int)0x0000000000FF0000);
                        gen.Emit(OpCodes.Conv_I8);
                        gen.Emit(OpCodes.Ldarg_1);
                        gen.Emit(OpCodes.Ldc_I4_S, (byte)24); // >> 24
                        gen.Emit(OpCodes.Shr_Un);
                        gen.Emit(OpCodes.And);
                        gen.Emit(OpCodes.Or);

                        //(0x00000000FF000000) & (value >> 8) |
                        gen.Emit(OpCodes.Ldc_I4, (int)0x00000000FF000000);
                        gen.Emit(OpCodes.Conv_U8);
                        gen.Emit(OpCodes.Ldarg_1);
                        gen.Emit(OpCodes.Ldc_I4_8); // >> 8
                        gen.Emit(OpCodes.Shr_Un);
                        gen.Emit(OpCodes.And);
                        gen.Emit(OpCodes.Or);

                        //(0x000000FF00000000) & (value << 8) |
                        gen.Emit(OpCodes.Ldc_I8, (long)0x000000FF00000000); //64bit INT
                        gen.Emit(OpCodes.Ldarg_1);
                        gen.Emit(OpCodes.Ldc_I4_8); // << 8
                        gen.Emit(OpCodes.Shl);
                        gen.Emit(OpCodes.And);
                        gen.Emit(OpCodes.Or);

                        //(0x0000FF0000000000) & (value << 24) |
                        gen.Emit(OpCodes.Ldc_I8, (long)0x0000FF0000000000); //64bit INT
                        gen.Emit(OpCodes.Ldarg_1);
                        gen.Emit(OpCodes.Ldc_I4_S, (byte)24); // << 24
                        gen.Emit(OpCodes.Shl);
                        gen.Emit(OpCodes.And);
                        gen.Emit(OpCodes.Or);

                        //(0x00FF000000000000) & (value << 40) |
                        gen.Emit(OpCodes.Ldc_I8, (long)0x00FF000000000000); //64bit INT
                        gen.Emit(OpCodes.Ldarg_1);
                        gen.Emit(OpCodes.Ldc_I4_S, (byte)40); // << 40
                        gen.Emit(OpCodes.Shl);
                        gen.Emit(OpCodes.And);
                        gen.Emit(OpCodes.Or);

                        //(0xFF00000000000000) & (value << 56)
                        gen.Emit(OpCodes.Ldc_I8, (long)0xFF00000000000000); //64bit INT
                        gen.Emit(OpCodes.Ldarg_1);
                        gen.Emit(OpCodes.Ldc_I4_S, (byte)56); // << 56
                        gen.Emit(OpCodes.Shl);
                        gen.Emit(OpCodes.And);
                        gen.Emit(OpCodes.Or);
                        gen.Emit(OpCodes.Starg_S, 1);
                    }
                    break;
                }
            }
        }

        private void CreateByteMethod(TypeBuilder typeBuilder)
        {
            MethodBuilder mb = typeBuilder.DefineMethod("CalculateByte", MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.NewSlot | MethodAttributes.Virtual | MethodAttributes.Final, Type.GetType("System.Void"), new Type[] { typeof(byte) });
            ILGenerator gen = mb.GetILGenerator();
            /*gen.Emit(OpCodes.Ldarg_1);
            gen.Emit(OpCodes.Ldc_I4_S, 50);
            gen.Emit(OpCodes.Conv_I8);
            gen.Emit(OpCodes.Starg_S, 1);

            gen.Emit(OpCodes.Ldarg_1);*/
            gen.Emit(OpCodes.Ret);

            MethodInfo sayHelloMethod = typeof(IAlgorithm).GetMethod("CalculateByte");
            typeBuilder.DefineMethodOverride(mb, sayHelloMethod);
        }

        public void Dispose()
        {
            Algorithm = null;
            typeBuilder = null;
            modBuilder = null;
            assemblyName = null;
            asmBuilder = null;
        }
    }
}