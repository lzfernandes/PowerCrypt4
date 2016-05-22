using System;
using System.Numerics;
using System.Xml;

namespace OmniBean.PowerCrypt4
{
    /// <summary>
    ///     Utility class for RSAProvider
    /// </summary>
    public class RSAProviderUtils
    {
        /// <summary>
        ///     Creates a RSAProviderParameters class from a given XMLKeyInfo string.
        /// </summary>
        /// <param name="XMLKeyInfo">Key Data.</param>
        /// <param name="ModulusSize">RSA Modulus Size</param>
        /// <returns>RSAProviderParameters class</returns>
        public static RSAProviderParameters GetRSAProviderParameters(string XMLKeyInfo, int ModulusSize)
        {
            var Has_CRT_Info = false;
            var Has_PRIVATE_Info = false;
            var Has_PUBLIC_Info = false;

            var doc = new XmlDocument();
            try
            {
                doc.LoadXml(XMLKeyInfo);
            }
            catch (Exception ex)
            {
                throw new Exception("Malformed KeyInfo XML: " + ex.Message);
            }

            var Modulus = new byte[0];
            var Exponent = new byte[0];
            var D = new byte[0];
            var P = new byte[0];
            var Q = new byte[0];
            var DP = new byte[0];
            var DQ = new byte[0];
            var InverseQ = new byte[0];

            try
            {
                Modulus = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Modulus").InnerText);
                Exponent = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Exponent").InnerText);
                Has_PUBLIC_Info = true;
            }
            catch
            {
            }

            try
            {
                Modulus = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Modulus").InnerText);
                D = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("D").InnerText);
                Exponent = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Exponent").InnerText);
                Has_PRIVATE_Info = true;
            }
            catch
            {
            }

            try
            {
                Modulus = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Modulus").InnerText);
                P = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("P").InnerText);
                Q = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Q").InnerText);
                DP = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("DP").InnerText);
                DQ = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("DQ").InnerText);
                InverseQ = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("InverseQ").InnerText);
                Has_CRT_Info = true;
            }
            catch
            {
            }

            if (Has_CRT_Info && Has_PRIVATE_Info)
            {
                return new RSAProviderParameters(Modulus, Exponent, D, P, Q, DP, DQ, InverseQ, ModulusSize);
            }
            if (Has_PRIVATE_Info)
            {
                return new RSAProviderParameters(Modulus, Exponent, D, ModulusSize);
            }
            if (Has_PUBLIC_Info)
            {
                return new RSAProviderParameters(Modulus, Exponent, ModulusSize);
            }

            throw new Exception("Could not process XMLKeyInfo. Incomplete key information.");
        }

        /// <summary>
        ///     Converts a non-negative integer to an octet string of a specified length.
        /// </summary>
        /// <param name="x">The integer to convert.</param>
        /// <param name="xLen">Length of output octets.</param>
        /// <param name="makeLittleEndian">If True little-endian converntion is followed, big-endian otherwise.</param>
        /// <returns></returns>
        public static byte[] I2OSP(BigInteger x, int xLen, bool makeLittleEndian)
        {
            var result = new byte[xLen];
            var index = 0;
            while ((x > 0) && (index < result.Length))
            {
                result[index++] = (byte) (x%256);
                x /= 256;
            }
            if (!makeLittleEndian)
                Array.Reverse(result);
            return result;
        }

        /// <summary>
        ///     Converts a byte array to a non-negative integer.
        /// </summary>
        /// <param name="data">The number in the form of a byte array.</param>
        /// <param name="isLittleEndian">Endianness of the byte array.</param>
        /// <returns>An non-negative integer from the byte array of the specified endianness.</returns>
        public static BigInteger OS2IP(byte[] data, bool isLittleEndian)
        {
            BigInteger bi = 0;
            if (isLittleEndian)
            {
                for (var i = 0; i < data.Length; i++)
                {
                    bi += BigInteger.Pow(256, i)*data[i];
                }
            }
            else
            {
                for (var i = 1; i <= data.Length; i++)
                {
                    bi += BigInteger.Pow(256, i - 1)*data[data.Length - i];
                }
            }
            return bi;
        }

        /// <summary>
        ///     Performs Bitwise Ex-OR operation to two given byte arrays.
        /// </summary>
        /// <param name="A">The first byte array.</param>
        /// <param name="B">The second byte array.</param>
        /// <returns>The bitwise Ex-OR result.</returns>
        public static byte[] XOR(byte[] A, byte[] B)
        {
            if (A.Length != B.Length)
            {
                throw new ArgumentException("XOR: Parameter length mismatch");
            }
            var R = new byte[A.Length];

            for (var i = 0; i < A.Length; i++)
            {
                R[i] = (byte) (A[i] ^ B[i]);
            }
            return R;
        }

        internal static void FixByteArraySign(ref byte[] bytes)
        {
            if ((bytes[bytes.Length - 1] & 0x80) > 0)
            {
                var temp = new byte[bytes.Length];
                Array.Copy(bytes, temp, bytes.Length);
                bytes = new byte[temp.Length + 1];
                Array.Copy(temp, bytes, temp.Length);
            }
        }
    }
}