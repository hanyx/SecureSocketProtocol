using SecureSocketProtocol3;
using SecureSocketProtocol3.Utils;
using System;

// Wiktor Zychla, 19.VII.2002

namespace vicMazeGen
{
	public class cVaria
	{
		/// <summary>
		/// Check if the string is numeric.
		/// </summary>
		/// <param name="s"></param>
		/// <returns></returns>
		public static bool IsNumeric( string s )
		{
			try
			{
				int i = int.Parse( s );
				return true;
			}
			catch(Exception ex)
			{
                SysLogger.Log(ex.Message, SysLogType.Error);
				return false;
			}
		}

		private cVaria() {}
	}
}
