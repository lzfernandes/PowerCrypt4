using System.Security.Cryptography;
using OmniBean.PowerCrypt4.Utilities;

namespace OmniBean.PowerCrypt4
{
    public static class HashUtils
    {
        public static string SHA512(string data)
        {
            byte[] hash;
            using (SHA512 shaM = new SHA512Managed())
            {
                hash = shaM.ComputeHash(data.GetBytes());
            }
            return AESProvider.HexString(hash);
        }

        public static string SHA256(string data)
        {
            byte[] hash;
            using (SHA256 shaM = new SHA256Managed())
            {
                hash = shaM.ComputeHash(data.GetBytes());
            }
            return AESProvider.HexString(hash);
        }

        public static string SHA384(string data)
        {
            byte[] hash;
            using (SHA384 shaM = new SHA384Managed())
            {
                hash = shaM.ComputeHash(data.GetBytes());
            }
            return AESProvider.HexString(hash);
        }
    }
}