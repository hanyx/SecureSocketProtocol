using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Text;
using System.Windows.Forms;
using System.Drawing.Drawing2D;

/*
    The MIT License (MIT)

    Copyright (c) 2016 AnguisCaptor

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace SecureSocketProtocol3.Controls
{
    public partial class uTorrentProgressBar : UserControl, IDisposable
    {
        /*
         * This progressbar is a attempt to re-create the progressbar from uTorrent
         * By DragonHunter and Justin
         * 
         *  Credits:
         *  DragonHunter
         *  Justin (Classmate)
         */

        private BufferedGraphics bg;
        private object locky = new object();
        private SortedList<int, ProgressBarExPiece> pieces;
        private int PieceCounter = 0;
        private int _MaxValue = 100;

        /// <summary> The maximum value for the Value property. </summary>
        [Category("Value"), DefaultValue(100), Description("The maximum value for the Value property.")]
        public int MaxValue
        {
            get { return _MaxValue; }
            set
            {
                if (value > 0)
                {
                    _MaxValue = value;
                    this.RedrawProgressBar();
                }
            }
        }

        public Color ProgressBarColor
        {
            get;
            set;
        }


        public bool AllowAlpha
        {
            get;
            set;
        }

        public uTorrentProgressBar()
        {
            InitializeComponent();
            this.pieces = new SortedList<int, ProgressBarExPiece>();
            this.bg = new BufferedGraphicsContext().Allocate(this.CreateGraphics(), this.ClientRectangle);
            HSLColor BackColor = Color.FromArgb(255, 240, 243, 249);
            BackColor.Hue = 147;
            BackColor.Luminosity = 230;
            BackColor.Saturation = 103;
            this.BackColor = BackColor;

            HSLColor ProgressColor = Color.FromArgb(255, 171, 214, 121);
            ProgressColor.Hue = 58;
            ProgressColor.Luminosity = 158;
            ProgressColor.Saturation = 124;
            this.ProgressBarColor = ProgressColor;
        }

        public void RedrawProgressBar()
        {
            lock (locky)
            {
                bg.Graphics.Clear(this.BackColor);

                HSLColor BorderColor = Color.FromArgb(255, 240, 240, 240);
                BorderColor.Hue = 160;
                BorderColor.Luminosity = 226;
                BorderColor.Saturation = 0;
                bg.Graphics.DrawRectangle(new Pen(BorderColor), new Rectangle(0, 0, this.Width - 1, this.Height - 1));

                if (pieces.Count > 0)
                {
                    float PieceWidth = (float)(this.Width - 2) / (float)pieces.Count;
                    float xOffset = 0;
                    float Multiplier = (float)pieces.Count / (float)(this.Width - 2);
                    Multiplier = (Multiplier < 1F ? 1F : Multiplier);

                    for (int i = 0; i < pieces.Count; i++)
                    {
                        float place = (int)((float)i / Multiplier);
                        xOffset = (PieceWidth * place) * Multiplier;
                        GraphicsPath path = new GraphicsPath();
                        path.AddPolygon(new Point[]
                        {
                            new Point((int)xOffset + 1, 1),
                            new Point((int)xOffset + (int)Math.Ceiling(pieces.Values[i].RenderWidth) + 1, 1),
                            new Point((int)xOffset + (int)Math.Ceiling(pieces.Values[i].RenderWidth) + 1, this.Height - 1),
                            new Point((int)xOffset + 1, this.Height - 1),
                        });

                        if (AllowAlpha)
                        {
                            int alpha = (int)(255f * ((1f / ((float)_MaxValue / (float)pieces.Values[i].Value)) / Multiplier));
                            ProgressBarColor = Color.FromArgb((alpha < 230) ? alpha + 25 : alpha, ProgressBarColor.R, ProgressBarColor.G, ProgressBarColor.B);
                        }

                        bg.Graphics.FillPath(new SolidBrush(ProgressBarColor), path);
                    }
                }
                bg.Render();
            }
        }

        private void ProgressBarEx_Paint(object sender, PaintEventArgs e)
        {
            RedrawProgressBar();
        }

        private void ProgressBarEx_SizeChanged(object sender, EventArgs e)
        {
            lock (locky)
            {
                this.bg.Dispose();
                this.bg = new BufferedGraphicsContext().Allocate(this.CreateGraphics(), this.ClientRectangle);
                CalcWidth();
            }
        }

        public ProgressBarExPiece AddPiece()
        {
            lock (locky)
            {
                ProgressBarExPiece piece = new ProgressBarExPiece();
                piece.ProgressBarEx = this;
                piece.ItemId = PieceCounter;
                pieces.Add(piece.ItemId, piece);
                PieceCounter++;
                CalcWidth();
                this.RedrawProgressBar();
                return piece;
            }
        }

        public ProgressBarExPiece AddPiece(int PieceId)
        {
            lock (locky)
            {
                ProgressBarExPiece piece = new ProgressBarExPiece();
                piece.ProgressBarEx = this;
                piece.ItemId = PieceCounter;
                pieces.Add(piece.ItemId, piece);
                PieceCounter++;
                CalcWidth();
                this.RedrawProgressBar();
                return piece;
            }
        }

        public void RemovePiece(ProgressBarExPiece piece)
        {
            lock (locky)
            {
                if (pieces.ContainsKey(piece.ItemId))
                    pieces.Remove(piece.ItemId);
                CalcWidth();
            }
        }

        public void RemoveAllPieces()
        {
            lock (locky)
            {
                pieces.Clear();
                CalcWidth();
            }
        }

        public ProgressBarExPiece GetPiece(int PieceId)
        {
            lock (locky)
            {
                if (pieces.ContainsKey(PieceId))
                    return pieces[PieceId];
                return null;
            }
        }

        public void CalcWidth()
        {
            lock (locky)
            {
                for (int i = 0; i < pieces.Count; i++)
                {
                    float width = (float)this.Width / (float)((pieces.Count == 0) ? 1 : pieces.Count);
                    pieces.Values[i].Width = width;
                }
            }
        }
    }

    public class ProgressBarExPiece
    {
        internal uTorrentProgressBar ProgressBarEx;
        internal int ItemId = 0;
        internal float Width = 0;
        internal int _Value = 0;

        public int Value
        {
            get { return _Value; }
            set
            {
                _Value = value;
                ProgressBarEx.RedrawProgressBar();
            }
        }

        public float Percent
        {
            get
            {
                return ((float)Value / (float)ProgressBarEx.MaxValue * 100F);
            }
        }

        internal float RenderWidth
        {
            get
            {
                return (float)this.Width * (Percent / 100F);
            }
        }

        public ProgressBarExPiece()
        {

        }
    }
}
