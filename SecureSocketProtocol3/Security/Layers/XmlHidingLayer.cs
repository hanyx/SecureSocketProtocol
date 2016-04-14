using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.Layers
{
    public class XmlHidingLayer : ILayer
    {
        SecureRandom rnd = new SecureRandom();

        private string GetRootElementName
        {
            get
            {
                string[] RootElementNames = new string[]
                {
                    "Contact-Info",
                    "Contacts",
                    "Play-List",
                    "Songs",
                    "Pet-Names"
                };

                int RandomNum = rnd.Next(0, RootElementNames.Length);
                return RootElementNames[RandomNum];
            }
        }

        public XmlHidingLayer()
        {

        }

        public LayerType Type
        {
            get { return LayerType.Encryption; }
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            string kek = GetRandomString();
            string ok = "";
            try
            {
                using (MemoryStream OutMs = new MemoryStream())
                using (System.Xml.XmlWriter writer = System.Xml.XmlWriter.Create(OutMs))
                {
                    int read = 0;
                    int offset = InOffset;

                    writer.WriteStartDocument();
                    writer.WriteStartElement(GetRootElementName);

                    while (read < InLen)
                    {
                        int CanRead = InLen - read;
                        int Length = rnd.Next(1, CanRead > 64 ? 64 : CanRead);
                        string HexString = Convert.ToBase64String(InData, offset, Length);

                        kek = GetRandomString();
                        ok = HexString;
                        writer.WriteElementString(kek, ok);

                        read += Length;
                        offset += Length;
                    }

                    writer.WriteEndElement();
                    writer.WriteEndDocument();
                    writer.Flush();

                    OutData = OutMs.ToArray();
                    OutOffset = 0;
                    OutLen = OutData.Length;
                }
            }
            catch { }
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            try
            {
                using (MemoryStream stream = new MemoryStream(InData, InOffset, InLen, false))
                using (MemoryStream outStream = new MemoryStream())
                {
                    System.Xml.XmlDocument doc = new System.Xml.XmlDocument();
                    doc.Load(stream);

                    System.Xml.XmlNode node = doc.ChildNodes[1];

                    for (int i = 0; i < node.ChildNodes.Count; i++)
                    {
                        byte[] Data = Convert.FromBase64String(node.ChildNodes[i].InnerText);
                        outStream.Write(Data, 0, Data.Length);
                    }

                    OutData = outStream.GetBuffer();
                    OutOffset = 0;
                    OutLen = (int)outStream.Length;
                }
            }
            catch { }
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {

        }

        private string GetRandomString()
        {
            const string Chars = "QAZWSXEDCRFVTGBYHNUJMIKOLPqazwsxedcrfvtgbyhnujmikolp";
            string ret = "";
            int CharLength = rnd.Next(2, 7);

            for (int i = 0; i < CharLength; i++)
                ret += Chars[rnd.Next(0, Chars.Length)];

            if (ret == "")
            {

            }

            return ret;
        }
    }
}