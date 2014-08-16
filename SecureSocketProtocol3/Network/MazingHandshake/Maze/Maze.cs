using System;
using System.Collections;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;

// Wiktor Zychla, started 19.VII.2002
// v.0.02 - added smoothness

namespace vicMazeGen
{
	public class Maze
	{
		public enum Direction 
		{
			N = 1,
			W = 2
		}

		Stack  s_stack;
		Random r;

		public int     MSIZEX;
		public int     MSIZEY;
		public int []  maze_base;
		public byte[,] maze_data;

		private int iSmooth;

		#region Generating

		/// <summary>
		/// Just do some initialization and call the main routine,
		/// that is analyze_cell()
		/// </summary>
		/// <param name="sizeX"></param>
		/// <param name="sizeY"></param>
		/// <param name="seed"></param>
		public void GenerateMaze( int sizeX, int sizeY, int seed, int smoothness )
		{
			iSmooth = smoothness;
			MSIZEX  = sizeX;
			MSIZEY  = sizeY;
			maze_base = new int[MSIZEX*MSIZEY];
			maze_data = new Byte[MSIZEX, MSIZEY];

			s_stack = new Stack();
			r = new Random ( seed );

			MazeInit( r );
			
			cMazeState s = new cMazeState(r.Next()%MSIZEX, r.Next()%MSIZEY, 0);
			analyze_cell( s, r );
		}

		/// <summary>
		/// This is the main routine.
		/// The algorithm is pretty simple and very efficient.
		/// At the beginnins there are walls everywhere.
		/// 
		/// The algorithm walks around the maze choosing the
		/// random path at every step and looks if it can
		/// remove the wall between the cells.
		/// 
		/// The test that allows to remove the wall is also really
		/// simple: if the two cells are already connected then
		/// the wall is not allowed.
		/// 
		/// The only trick is the check whether the two cells are
		/// connected. To answer this question, the algorithm
		/// keeps the chains of connected walls. It works like this:
		/// - each chain consist of pointers to consecutive cells
		///   in the chain, last pointer is -1 and the cell with 
		///   such value in maze_base is called base_cell of a cell. 
		/// - at the beginning there are no chains, looking
		///   at maze_base[cellindex] you can find the value of -1
		/// - when two chains are merged, the pointer of the base cell
		///   of one of chains is changed so that it points to the 
		///   base_cell of the other chain.
		///   
		/// I've read about a similar trick by Tarjan but it looked
		/// much complicated ( or maybe I didn't understand it well ).
		/// Nevertheless, my code works really fast! Try to beat it.  
		/// </summary>
		/// <param name="s"></param>
		/// <param name="r"></param>
		void analyze_cell( cMazeState s, Random r )
		{			
			bool bEnd = false, found;
			int indexSrc, indexDest, tDir=0, prevDir=0;			

			while (true)
			{
				if ( s.dir == 15 )
				{
					while ( s.dir == 15 )
					{
						s = (cMazeState)s_stack.pop();
						if ( s == null ) 
						{
							bEnd = true;
							break;
						}
					}
					if ( bEnd == true ) break;
				}
				else
				{
					do
					{
						prevDir = tDir;
						tDir = (int)Math.Pow( 2, r.Next()%4 );
						
						if ( (r.Next()%32) < iSmooth )
							if ( (s.dir & prevDir) == 0 )
								tDir = prevDir;

						if ( (s.dir & tDir) != 0 )
							found = true;
						else
							found = false;
					} while ( found == true && s.dir!=15 );
					
					s.dir |= tDir;
					
					indexSrc  = cell_index( s.x, s.y );
					
					// direction W
					if ( tDir == 1 && s.x > 0 )
					{
						indexDest = cell_index( s.x-1, s.y );
						if ( base_cell( indexSrc ) != base_cell ( indexDest ) )
						{
							merge( indexSrc, indexDest );
							maze_data[s.x, s.y] |= (byte)Direction.W;
							
							s_stack.push ( new cMazeState(s) );
							s.x -= 1;s.dir = 0;
						}
					}
		
					// direction E
					if ( tDir == 2 && s.x < MSIZEX-1 )
					{
						indexDest = cell_index( s.x+1, s.y );
						if ( base_cell( indexSrc ) != base_cell ( indexDest ) )
						{
							merge( indexSrc, indexDest );
							maze_data[s.x+1, s.y] |= (byte)Direction.W;

							s_stack.push ( new cMazeState(s) );
							s.x += 1;s.dir = 0;
						}
					}
		
					// direction N
					if ( tDir == 4 && s.y > 0 )
					{
						indexDest = cell_index( s.x, s.y-1 );
						if ( base_cell( indexSrc ) != base_cell ( indexDest ) )
						{
							merge( indexSrc, indexDest );
							maze_data[s.x, s.y] |= (byte)Direction.N;

							s_stack.push ( new cMazeState(s) );
							s.y -= 1;s.dir = 0;
						}
					}
		
					// direction S
					if ( tDir == 8 && s.y < MSIZEY-1 )
					{
						indexDest = cell_index( s.x, s.y+1 );
						if ( base_cell( indexSrc ) != base_cell ( indexDest ) )
						{
							merge( indexSrc, indexDest );
							maze_data[s.x, s.y+1] |= (byte)Direction.N;

							s_stack.push ( new cMazeState(s) );
							s.y += 1;s.dir = 0;
						}
					}
				} // else
			} // while 
		} // function

		#endregion
		#region Bitmap
		public Bitmap GetBitmap(int xS, int yS)
		{
			int i, j;

			Bitmap tB = new Bitmap( xS+1, yS+1 );
			Graphics g = Graphics.FromImage( (Image)tB );

			Brush w = Brushes.White;
			Brush r = Brushes.Red;
			Brush b = Brushes.Blue;

			Pen   bp = new Pen( b, 1 );
			Pen   rp = new Pen( r, 1 );

			// background
			g.FillRectangle( w , 0, 0, tB.Width-1, tB.Height-1 );
			g.DrawRectangle( bp, 0, 0, tB.Width-1, tB.Height-1 );
			
			int xSize = xS / MSIZEX;
			int ySize = yS / MSIZEY;

			for ( i=0; i<MSIZEX; i++ )
				for ( j=0; j<MSIZEY; j++ )
				{	
					// inspect the maze
					if ( (maze_data[i, j] & (byte)Direction.N) == 0 )
						g.DrawLine( bp, 
							new Point( xSize * i    , ySize * j ), 
							new Point( xSize * (i+1), ySize * j ) );

					if ( (maze_data[i, j] & (byte)Direction.W) == 0 )
						g.DrawLine( bp, 
							new Point( xSize * i, ySize * j ), 
							new Point( xSize * i, ySize * (j+1) ) );

				}
	
			// start & end
			g.DrawLine( rp, 0, 0, xSize, 0 );
			g.DrawLine( rp, 0, 0, 0, xSize );
			g.DrawLine( rp, xS, yS, xS-xSize, yS );
			g.DrawLine( rp, xS, yS, xS, yS-ySize );

			g.Dispose();

			return tB;
		}
		#endregion
		#region Solving
		/// <summary>
		/// Znajduje przejcie labiryntu midzy zadanymi punktami
		/// </summary>
		/// <returns>Lista kolejnych cCellPosition, ktre stanowi rozwizanie</returns>
		public ArrayList Solve(int xSource, int ySource, int xDest, int yDest, int maxSteps)
		{
			int[,] tMazePath   = new int[MSIZEX, MSIZEY];
			bool   destReached = false;

			cCellPosition cellPos = new cCellPosition( xSource, ySource );			
			ArrayList     calcState = new ArrayList();

			// przygotowanie do rozpoczcia
			calcState.Add ( cellPos );

			int step = 0;
			for (int i=0; i<MSIZEX; i++)
				for (int j=0; j<MSIZEY; j++)
					tMazePath[i,j] = -1;
			tMazePath[xSource, ySource] = step;	

			// zabezpieczenia
			if ( maze_data == null ) return null;
			if ( xSource == xDest && ySource == yDest ) return calcState;

			while ( destReached == false && calcState.Count > 0 )
			{
				step++;
				ArrayList calcNextState = new ArrayList();

				for (int i=0; i<calcState.Count; i++)
				{					
					cCellPosition calcCPos = (cCellPosition)calcState[i];
					// sprawd cztery ssiadujce kierunki
					// N
					if ( calcCPos.y > 0 ) // tylko jesli w zakresie
						if ( tMazePath[calcCPos.x, calcCPos.y-1] == -1 ) // i jeszcze tam nie bylismy
							if ( (maze_data[calcCPos.x, calcCPos.y] & (byte)Direction.N) != 0 ) // a mozna tam isc
							{
								tMazePath[calcCPos.x, calcCPos.y-1] = step;
								cCellPosition calcNextCPos = new cCellPosition( calcCPos.x, calcCPos.y-1 );
								calcNextState.Add ( calcNextCPos ); 

								if ( calcNextCPos.x == xDest && calcNextCPos.y == yDest ) destReached = true;
							}
					// W
					if ( calcCPos.x > 0 ) // tylko jesli w zakresie
						if ( tMazePath[calcCPos.x-1, calcCPos.y] == -1 ) // i jeszcze tam nie bylismy
							if ( (maze_data[calcCPos.x, calcCPos.y] & (byte)Direction.W) != 0 ) // a mozna tam isc
							{
								tMazePath[calcCPos.x-1, calcCPos.y] = step;
								cCellPosition calcNextCPos = new cCellPosition( calcCPos.x-1, calcCPos.y );
								calcNextState.Add ( calcNextCPos ); 

								if ( calcNextCPos.x == xDest && calcNextCPos.y == yDest ) destReached = true;
							}
					// S
					if ( calcCPos.y < MSIZEY-1 ) // tylko jesli w zakresie
						if ( tMazePath[calcCPos.x, calcCPos.y+1] == -1 ) // i jeszcze tam nie bylismy
							if ( (maze_data[calcCPos.x, calcCPos.y+1] & (byte)Direction.N) != 0 ) // a mozna tam isc
							{
								tMazePath[calcCPos.x, calcCPos.y+1] = step;
								cCellPosition calcNextCPos = new cCellPosition( calcCPos.x, calcCPos.y+1 );
								calcNextState.Add ( calcNextCPos ); 

								if ( calcNextCPos.x == xDest && calcNextCPos.y == yDest ) destReached = true;
							}
					// E
					if ( calcCPos.x < MSIZEX-1 ) // tylko jesli w zakresie
						if ( tMazePath[calcCPos.x+1, calcCPos.y] == -1 ) // i jeszcze tam nie bylismy
							if ( (maze_data[calcCPos.x+1, calcCPos.y] & (byte)Direction.W) != 0 ) // a mozna tam isc
							{
								tMazePath[calcCPos.x+1, calcCPos.y] = step;
								cCellPosition calcNextCPos = new cCellPosition( calcCPos.x+1, calcCPos.y );
								calcNextState.Add ( calcNextCPos ); 

								if ( calcNextCPos.x == xDest && calcNextCPos.y == yDest ) destReached = true;
							}
				}
				calcState = calcNextState;
			}
			// moliwe s dwa warianty:
			if ( destReached == false ) 
				return null;
			else
			{
				tMazePath[xDest, yDest] = step;
				// buduj drog przez tMazePath
				ArrayList pPath = new ArrayList();

				int tx = xDest;
				int ty = yDest;
	
				pPath.Add ( new cCellPosition ( tx, ty ) );

				bool stepExists;

				while ( tx != xSource || ty != ySource )
				{
					step       = tMazePath[tx, ty];
					stepExists = false;
					
					// szukaj kroku 
					// N
					if ( ty > 0 && stepExists == false  )
						if ( tMazePath[tx, ty-1] == step-1 && 
						     (maze_data[tx, ty] & (byte)Direction.N) != 0 
						   )
						{
							ty -= 1; stepExists = true;
							pPath.Add ( new cCellPosition ( tx, ty ) );
						}
					// W	
					if ( tx > 0 && stepExists == false )
						if ( tMazePath[tx-1, ty] == step-1 &&
						     (maze_data[tx, ty] & (byte)Direction.W) != 0 
						   )
						{
							tx -= 1; stepExists = true;
							pPath.Add ( new cCellPosition ( tx, ty ) );
						}
					// S	
					if ( ty < MSIZEY -1 && stepExists == false )
						if ( tMazePath[tx, ty+1] == step-1 &&
						     (maze_data[tx, ty+1] & (byte)Direction.N) != 0 
						   )
						{
							ty += 1; stepExists = true;
							pPath.Add ( new cCellPosition ( tx, ty ) );
						}
					// E	
					if ( tx < MSIZEX - 1 && stepExists == false )
						if ( tMazePath[tx+1, ty] == step-1 &&
						     (maze_data[tx+1, ty] & (byte)Direction.W) != 0 
						   )
						{
							tx += 1; stepExists = true;
							pPath.Add ( new cCellPosition ( tx, ty ) );
						}
					
					if ( stepExists == false )
                        return null;
                    if (pPath.Count > maxSteps)
                        break;
				}

				return pPath;

			}
		}
		#endregion
		#region Cell functions
		int cell_index( int x, int y )
		{
			return MSIZEX * y + x;
		}
		int base_cell( int tIndex )
		{
			int index = tIndex;
			while ( maze_base[ index ] >= 0 )
			{
				index = maze_base[ index ];
			}
			return index;
		}
		void merge( int index1, int index2 )
		{
			// merge both lists
			int base1 = base_cell( index1 );
			int base2 = base_cell( index2 );
			maze_base[ base2 ] = base1;
		}
		#endregion
		#region MazeInit
		void MazeInit( Random r )
		{
			int i, j;
			
			// maze data
			for (i=0; i<MSIZEX; i++)
				for (j=0; j<MSIZEY; j++)
				{
					maze_base [cell_index(i, j)] = -1;
					maze_data [i, j] = 0;
				}			
		}


		#endregion

		public Maze() {}	
	}

	/// <summary>
	/// A signle state of maze iteration. 
	/// </summary>
	public class cMazeState
	{
		public int x, y, dir;
		public cMazeState( int tx, int ty, int td ) { x=tx; y=ty; dir = td; }
		public cMazeState( cMazeState s ) { x=s.x; y=s.y; dir=s.dir; }
	}	

	public class cCellPosition
	{
		public int x, y;
		public cCellPosition() {}
		public cCellPosition( int xp, int yp ) { x = xp; y = yp; }
	}
}
