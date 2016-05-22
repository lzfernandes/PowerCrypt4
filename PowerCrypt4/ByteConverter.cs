/*
 */

using System;
using System.Text;

namespace OmniBean.PowerCrypt4.Utilities
{
    public static class ByteConverter
    {
        public static byte[] GetBytes(this string str)
        {
            var iso = Encoding.GetEncoding("ISO-8859-1");
            return iso.GetBytes(str);
        }

        public static string GetString(this byte[] bytes)
        {
            var iso = Encoding.GetEncoding("ISO-8859-1");
            return iso.GetString(bytes);
        }

        public static byte[] RawGetBytes(this string str)
        {
            var bytes = new byte[str.Length*sizeof(char)];
            Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string RawGetString(this byte[] bytes)
        {
            var chars = new char[bytes.Length/sizeof(char)];
            Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }
    }
}