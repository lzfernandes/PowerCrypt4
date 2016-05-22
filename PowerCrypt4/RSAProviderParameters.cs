using System;
using System.Numerics;
using System.Security.Cryptography;

namespace OmniBean.PowerCrypt4
{
    /// <summary>
    ///     Class to keep the basic RSA parameters like Keys, and other information.
    /// </summary>
    public class RSAProviderParameters : IDisposable
    {
        public enum RSAProviderHashAlgorithm
        {
            SHA1,
            SHA256,
            SHA512,
            UNDEFINED
        }

        private HashAlgorithm ha = SHA1.Create();

        /// <summary>
        ///     Initialize the RSA class. It's assumed that both the Public and Extended Private info are there.
        /// </summary>
        /// <param name="rsaParams">Preallocated RSAParameters containing the required keys.</param>
        /// <param name="ModulusSize">Modulus size in bits</param>
        public RSAProviderParameters(RSAParameters rsaParams, int ModulusSize)
        {
            // rsaParams;
            OctetsInModulus = ModulusSize/8;
            E = RSAProviderUtils.OS2IP(rsaParams.Exponent, false);
            D = RSAProviderUtils.OS2IP(rsaParams.D, false);
            N = RSAProviderUtils.OS2IP(rsaParams.Modulus, false);
            P = RSAProviderUtils.OS2IP(rsaParams.P, false);
            Q = RSAProviderUtils.OS2IP(rsaParams.Q, false);
            DP = RSAProviderUtils.OS2IP(rsaParams.DP, false);
            DQ = RSAProviderUtils.OS2IP(rsaParams.DQ, false);
            InverseQ = RSAProviderUtils.OS2IP(rsaParams.InverseQ, false);
            HasCRTInfo = true;
            Has_PUBLIC_Info = true;
            Has_PRIVATE_Info = true;
        }

        /// <summary>
        ///     Initialize the RSA class. Only the public parameters.
        /// </summary>
        /// <param name="Modulus">Modulus of the RSA key.</param>
        /// <param name="Exponent">Exponent of the RSA key</param>
        /// <param name="ModulusSize">Modulus size in number of bits. Ex: 512, 1024, 2048, 4096 etc.</param>
        public RSAProviderParameters(byte[] Modulus, byte[] Exponent, int ModulusSize)
        {
            // rsaParams;
            OctetsInModulus = ModulusSize/8;
            E = RSAProviderUtils.OS2IP(Exponent, false);
            N = RSAProviderUtils.OS2IP(Modulus, false);
            Has_PUBLIC_Info = true;
        }

        /// <summary>
        ///     Initialize the RSA class.
        /// </summary>
        /// <param name="Modulus">Modulus of the RSA key.</param>
        /// <param name="Exponent">Exponent of the RSA key</param>
        /// ///
        /// <param name="D">Exponent of the RSA key</param>
        /// <param name="ModulusSize">Modulus size in number of bits. Ex: 512, 1024, 2048, 4096 etc.</param>
        public RSAProviderParameters(byte[] Modulus, byte[] Exponent, byte[] D, int ModulusSize)
        {
            // rsaParams;
            OctetsInModulus = ModulusSize/8;
            E = RSAProviderUtils.OS2IP(Exponent, false);
            N = RSAProviderUtils.OS2IP(Modulus, false);
            this.D = RSAProviderUtils.OS2IP(D, false);
            Has_PUBLIC_Info = true;
            Has_PRIVATE_Info = true;
        }

        /// <summary>
        ///     Initialize the RSA class. For CRT.
        /// </summary>
        /// <param name="Modulus">Modulus of the RSA key.</param>
        /// <param name="Exponent">Exponent of the RSA key</param>
        /// ///
        /// <param name="D">Exponent of the RSA key</param>
        /// <param name="P">P paramater of RSA Algorithm.</param>
        /// <param name="Q">Q paramater of RSA Algorithm.</param>
        /// <param name="DP">DP paramater of RSA Algorithm.</param>
        /// <param name="DQ">DQ paramater of RSA Algorithm.</param>
        /// <param name="InverseQ">InverseQ paramater of RSA Algorithm.</param>
        /// <param name="ModulusSize">Modulus size in number of bits. Ex: 512, 1024, 2048, 4096 etc.</param>
        public RSAProviderParameters(byte[] Modulus, byte[] Exponent, byte[] D, byte[] P, byte[] Q, byte[] DP, byte[] DQ,
            byte[] InverseQ, int ModulusSize)
        {
            // rsaParams;
            OctetsInModulus = ModulusSize/8;
            E = RSAProviderUtils.OS2IP(Exponent, false);
            N = RSAProviderUtils.OS2IP(Modulus, false);
            this.D = RSAProviderUtils.OS2IP(D, false);
            this.P = RSAProviderUtils.OS2IP(P, false);
            this.Q = RSAProviderUtils.OS2IP(Q, false);
            this.DP = RSAProviderUtils.OS2IP(DP, false);
            this.DQ = RSAProviderUtils.OS2IP(DQ, false);
            this.InverseQ = RSAProviderUtils.OS2IP(InverseQ, false);
            HasCRTInfo = true;
            Has_PUBLIC_Info = true;
            Has_PRIVATE_Info = true;
        }

        /// <summary>
        ///     Gets and sets the HashAlgorithm for RSA-OAEP padding.
        /// </summary>
        public RSAProviderHashAlgorithm HashAlgorithm
        {
            get
            {
                var al = RSAProviderHashAlgorithm.UNDEFINED;
                switch (ha.GetType().ToString())
                {
                    case "SHA1":
                        al = RSAProviderHashAlgorithm.SHA1;
                        break;

                    case "SHA256":
                        al = RSAProviderHashAlgorithm.SHA256;
                        break;

                    case "SHA512":
                        al = RSAProviderHashAlgorithm.SHA512;
                        break;
                }
                return al;
            }

            set
            {
                switch (value)
                {
                    case RSAProviderHashAlgorithm.SHA1:
                        ha = SHA1.Create();
                        hLen = 20;
                        break;

                    case RSAProviderHashAlgorithm.SHA256:
                        ha = SHA256.Create();
                        hLen = 32;
                        break;

                    case RSAProviderHashAlgorithm.SHA512:
                        ha = SHA512.Create();
                        hLen = 64;
                        break;
                }
            }
        }

        public bool HasCRTInfo { get; }

        public bool Has_PRIVATE_Info { get; }

        public bool Has_PUBLIC_Info { get; }

        public int OctetsInModulus { get; }

        public BigInteger N { get; }

        public int hLen { get; private set; } = 20;

        public BigInteger P { get; }

        public BigInteger Q { get; }

        public BigInteger DP { get; }

        public BigInteger DQ { get; }

        public BigInteger InverseQ { get; }

        public BigInteger E { get; }

        public BigInteger D { get; }

        public void Dispose()
        {
            ha.Dispose();
        }

        /// <summary>
        ///     Computes the hash from the given data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>Hash of the data.</returns>
        public byte[] ComputeHash(byte[] data)
        {
            return ha.ComputeHash(data);
        }
    }
}