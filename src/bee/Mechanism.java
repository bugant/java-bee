/*
 *   Copyright (c) 2010 Matteo Centenaro
 *   
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *   
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *   
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */


package bee;
import com.sun.jna.*;

public class Mechanism
{
    private NativeLong mechanism;
    public static final int RSA_PKCS_KEY_PAIR_GEN = 0x00000000;
    public static final int RSA_PKCS = 0x00000001;
    public static final int RSA_9796 = 0x00000002;
    public static final int RSA_X_509 = 0x00000003;

    public static final int MD2_RSA_PKCS = 0x00000004;
    public static final int MD5_RSA_PKCS = 0x00000005;
    public static final int SHA1_RSA_PKCS = 0x00000006;

    public static final int RIPEMD128_RSA_PKCS = 0x00000007;
    public static final int RIPEMD160_RSA_PKCS = 0x00000008;
    public static final int RSA_PKCS_OAEP = 0x00000009;

    public static final int RSA_X9_31_KEY_PAIR_GEN = 0x0000000A;
    public static final int RSA_X9_31 = 0x0000000B;
    
    public static final int SHA1_RSA_X9_31 = 0x0000000C;
    public static final int RSA_PKCS_PSS = 0x0000000D;
    public static final int SHA1_RSA_PKCS_PSS = 0x0000000E;

    public static final int DSA_KEY_PAIR_GEN = 0x00000010;
    public static final int DSA = 0x00000011;
    public static final int DSA_SHA1 = 0x00000012;
    public static final int DH_PKCS_KEY_PAIR_GEN = 0x00000020;
    public static final int DH_PKCS_DERIVE = 0x00000021;

    public static final int X9_42_DH_KEY_PAIR_GEN = 0x00000030;
    public static final int X9_42_DH_DERIVE = 0x00000031;
    public static final int X9_42_DH_HYBRID_DERIVE = 0x00000032;
    public static final int X9_42_MQV_DERIVE = 0x00000033;

    public static final int SHA256_RSA_PKCS = 0x00000040;
    public static final int SHA384_RSA_PKCS = 0x00000041;
    public static final int SHA512_RSA_PKCS = 0x00000042;
    public static final int SHA256_RSA_PKCS_PSS = 0x00000043;
    public static final int SHA384_RSA_PKCS_PSS = 0x00000044;
    public static final int SHA512_RSA_PKCS_PSS = 0x00000045;

    public static final int SHA224_RSA_PKCS = 0x00000046;
    public static final int SHA224_RSA_PKCS_PSS = 0x00000047;

    public static final int RC2_KEY_GEN = 0x00000100;
    public static final int RC2_ECB = 0x00000101;
    public static final int RC2_CBC = 0x00000102;
    public static final int RC2_MAC = 0x00000103;

    public static final int RC2_MAC_GENERAL = 0x00000104;
    public static final int RC2_CBC_PAD = 0x00000105;

    public static final int RC4_KEY_GEN = 0x00000110;
    public static final int RC4 = 0x00000111;

    public static final int DES_KEY_GEN = 0x00000120;
    public static final int DES_ECB = 0x00000121;
    public static final int DES_CBC = 0x00000122;
    public static final int DES_MAC = 0x00000123;
    public static final int DES_MAC_GENERAL = 0x00000124;
    public static final int DES_CBC_PAD = 0x00000125;
    public static final int DES2_KEY_GEN = 0x00000130;
    public static final int DES3_KEY_GEN = 0x00000131;
    public static final int DES3_ECB = 0x00000132;
    public static final int DES3_CBC = 0x00000133;
    public static final int DES3_MAC = 0x00000134;
    public static final int DES3_MAC_GENERAL = 0x00000135;
    public static final int DES3_CBC_PAD = 0x00000136;

    public static final int CDMF_KEY_GEN = 0x00000140;
    public static final int CDMF_ECB = 0x00000141;
    public static final int CDMF_CBC = 0x00000142;
    public static final int CDMF_MAC = 0x00000143;
    public static final int CDMF_MAC_GENERAL = 0x00000144;
    public static final int CDMF_CBC_PAD = 0x00000145;


/* the following four DES mechanisms are new for v2.20 */

    public static final int DES_OFB64 = 0x00000150;
    public static final int DES_OFB8 = 0x00000151;
    public static final int DES_CFB64 = 0x00000152;
    public static final int DES_CFB8 = 0x00000153;


    public static final int MD2 = 0x00000200;


/* MD2_HMAC and MD2_HMAC_GENERAL are new for v2.0 */

    public static final int MD2_HMAC = 0x00000201;
    public static final int MD2_HMAC_GENERAL = 0x00000202;


    public static final int MD5 = 0x00000210;


/* MD5_HMAC and MD5_HMAC_GENERAL are new for v2.0 */

    public static final int MD5_HMAC = 0x00000211;
    public static final int MD5_HMAC_GENERAL = 0x00000212;


    public static final int SHA_1 = 0x00000220;


/* SHA_1_HMAC and SHA_1_HMAC_GENERAL are new for v2.0 */

    public static final int SHA_1_HMAC = 0x00000221;
    public static final int SHA_1_HMAC_GENERAL = 0x00000222;


/* RIPEMD128, RIPEMD128_HMAC,

 * RIPEMD128_HMAC_GENERAL, RIPEMD160, RIPEMD160_HMAC,
 
  * and RIPEMD160_HMAC_GENERAL are new for v2.10 */
  
    public static final int RIPEMD128 = 0x00000230;  
    public static final int RIPEMD128_HMAC = 0x00000231;  
    public static final int RIPEMD128_HMAC_GENERAL = 0x00000232;  
    public static final int RIPEMD160 = 0x00000240;  
    public static final int RIPEMD160_HMAC = 0x00000241;  
    public static final int RIPEMD160_HMAC_GENERAL = 0x00000242;  
  
  
  /* SHA256/384/512 are new for v2.20 */
  
    public static final int SHA256 = 0x00000250;  
    public static final int SHA256_HMAC = 0x00000251;  
    public static final int SHA256_HMAC_GENERAL = 0x00000252;  
  
  
  /* SHA-224 is new for PKCS #11 v2.20 amendment 3 */
  
    public static final int SHA224 = 0x00000255;  
    public static final int SHA224_HMAC = 0x00000256;  
    public static final int SHA224_HMAC_GENERAL = 0x00000257;  
  
  
    public static final int SHA384 = 0x00000260;  
    public static final int SHA384_HMAC = 0x00000261;  
    public static final int SHA384_HMAC_GENERAL = 0x00000262;  
    public static final int SHA512 = 0x00000270;  
    public static final int SHA512_HMAC = 0x00000271;  
    public static final int SHA512_HMAC_GENERAL = 0x00000272;  
  
  
  /* SecurID is new for PKCS #11 v2.20 amendment 1 */
  
    public static final int SECURID_KEY_GEN = 0x00000280;  
    public static final int SECURID = 0x00000282;  
  
  
  /* HOTP is new for PKCS #11 v2.20 amendment 1 */
  
    public static final int HOTP_KEY_GEN = 0x00000290;  
    public static final int HOTP = 0x00000291;  
  
  
  /* ACTI is new for PKCS #11 v2.20 amendment 1 */
  
    public static final int ACTI = 0x000002A0;  
    public static final int ACTI_KEY_GEN = 0x000002A1;  
  
  
  /* All of the following mechanisms are new for v2.0 */
  
  /* Note that CAST128 and CAST5 are the same algorithm */
  
    public static final int CAST_KEY_GEN = 0x00000300;  
    public static final int CAST_ECB = 0x00000301;  
    public static final int CAST_CBC = 0x00000302;  
    public static final int CAST_MAC = 0x00000303;  
    public static final int CAST_MAC_GENERAL = 0x00000304;  
    public static final int CAST_CBC_PAD = 0x00000305;  
    public static final int CAST3_KEY_GEN = 0x00000310;  
    public static final int CAST3_ECB = 0x00000311;  
    public static final int CAST3_CBC = 0x00000312;  
    public static final int CAST3_MAC = 0x00000313;  
    public static final int CAST3_MAC_GENERAL = 0x00000314;  
    public static final int CAST3_CBC_PAD = 0x00000315;  
    public static final int CAST5_KEY_GEN = 0x00000320;  
    public static final int CAST128_KEY_GEN = 0x00000320;  
    public static final int CAST5_ECB = 0x00000321;  
    public static final int CAST128_ECB = 0x00000321;  
    public static final int CAST5_CBC = 0x00000322;  
    public static final int CAST128_CBC = 0x00000322;  
    public static final int CAST5_MAC = 0x00000323;  
    public static final int CAST128_MAC = 0x00000323;  
    public static final int CAST5_MAC_GENERAL = 0x00000324;  
    public static final int CAST128_MAC_GENERAL = 0x00000324;  
    public static final int CAST5_CBC_PAD = 0x00000325;  
    public static final int CAST128_CBC_PAD = 0x00000325;  
    public static final int RC5_KEY_GEN = 0x00000330;  
    public static final int RC5_ECB = 0x00000331;  
    public static final int RC5_CBC = 0x00000332;  
    public static final int RC5_MAC = 0x00000333;  
    public static final int RC5_MAC_GENERAL = 0x00000334;  
    public static final int RC5_CBC_PAD = 0x00000335;  
    public static final int IDEA_KEY_GEN = 0x00000340;  
    public static final int IDEA_ECB = 0x00000341;  
    public static final int IDEA_CBC = 0x00000342;  
    public static final int IDEA_MAC = 0x00000343;  
    public static final int IDEA_MAC_GENERAL = 0x00000344;  
    public static final int IDEA_CBC_PAD = 0x00000345;  
    public static final int GENERIC_SECRET_KEY_GEN = 0x00000350;  
    public static final int CONCATENATE_BASE_AND_KEY = 0x00000360;  
    public static final int CONCATENATE_BASE_AND_DATA = 0x00000362;  
    public static final int CONCATENATE_DATA_AND_BASE = 0x00000363;  
    public static final int XOR_BASE_AND_DATA = 0x00000364;  
    public static final int EXTRACT_KEY_FROM_KEY = 0x00000365;  
    public static final int SSL3_PRE_MASTER_KEY_GEN = 0x00000370;  
    public static final int SSL3_MASTER_KEY_DERIVE = 0x00000371;  
    public static final int SSL3_KEY_AND_MAC_DERIVE = 0x00000372;  
  
  
  /* SSL3_MASTER_KEY_DERIVE_DH, TLS_PRE_MASTER_KEY_GEN,
   * TLS_MASTER_KEY_DERIVE, TLS_KEY_AND_MAC_DERIVE, and
    * TLS_MASTER_KEY_DERIVE_DH are new for v2.11 */
    
    public static final int SSL3_MASTER_KEY_DERIVE_DH = 0x00000373;    
    public static final int TLS_PRE_MASTER_KEY_GEN = 0x00000374;    
    public static final int TLS_MASTER_KEY_DERIVE = 0x00000375;    
    public static final int TLS_KEY_AND_MAC_DERIVE = 0x00000376;    
    public static final int TLS_MASTER_KEY_DERIVE_DH = 0x00000377;    
    
    
    /* TLS_PRF is new for v2.20 */
    
    public static final int TLS_PRF = 0x00000378;    
    
    
    public static final int SSL3_MD5_MAC = 0x00000380;    
    public static final int SSL3_SHA1_MAC = 0x00000381;    
    public static final int MD5_KEY_DERIVATION = 0x00000390;    
    public static final int MD2_KEY_DERIVATION = 0x00000391;    
    public static final int SHA1_KEY_DERIVATION = 0x00000392;    
    
    
    /* SHA256/384/512 are new for v2.20 */
    
    public static final int SHA256_KEY_DERIVATION = 0x00000393;    
    public static final int SHA384_KEY_DERIVATION = 0x00000394;    
    public static final int SHA512_KEY_DERIVATION = 0x00000395;    
    
    
    /* SHA-224 key derivation is new for PKCS #11 v2.20 amendment 3 */
    
    public static final int SHA224_KEY_DERIVATION = 0x00000396;    
    
    
    public static final int PBE_MD2_DES_CBC = 0x000003A0;    
    public static final int PBE_MD5_DES_CBC = 0x000003A1;    
    public static final int PBE_MD5_CAST_CBC = 0x000003A2;    
    public static final int PBE_MD5_CAST3_CBC = 0x000003A3;    
    public static final int PBE_MD5_CAST5_CBC = 0x000003A4;    
    public static final int PBE_MD5_CAST128_CBC = 0x000003A4;    
    public static final int PBE_SHA1_CAST5_CBC = 0x000003A5;    
    public static final int PBE_SHA1_CAST128_CBC = 0x000003A5;    
    public static final int PBE_SHA1_RC4_128 = 0x000003A6;    
    public static final int PBE_SHA1_RC4_40 = 0x000003A7;    
    public static final int PBE_SHA1_DES3_EDE_CBC = 0x000003A8;    
    public static final int PBE_SHA1_DES2_EDE_CBC = 0x000003A9;    
    public static final int PBE_SHA1_RC2_128_CBC = 0x000003AA;    
    public static final int PBE_SHA1_RC2_40_CBC = 0x000003AB;    
    
    
    /* PKCS5_PBKD2 is new for v2.10 */
    
    public static final int PKCS5_PBKD2 = 0x000003B0;    
    
    
    public static final int PBA_SHA1_WITH_SHA1_HMAC = 0x000003C0;    
    
    
    /* WTLS mechanisms are new for v2.20 */
    
    public static final int WTLS_PRE_MASTER_KEY_GEN = 0x000003D0;    
    public static final int WTLS_MASTER_KEY_DERIVE = 0x000003D1;    
    public static final int WTLS_MASTER_KEY_DERIVE_DH_ECC = 0x000003D2;    
    public static final int WTLS_PRF = 0x000003D3;    
    public static final int WTLS_SERVER_KEY_AND_MAC_DERIVE = 0x000003D4;    
    public static final int WTLS_CLIENT_KEY_AND_MAC_DERIVE = 0x000003D5;    
    
    
    public static final int KEY_WRAP_LYNKS = 0x00000400;    
    public static final int KEY_WRAP_SET_OAEP = 0x00000401;    
    
    
    /* CMS_SIG is new for v2.20 */
    
    public static final int CMS_SIG = 0x00000500;    
    
    
    /* KIP mechanisms are new for PKCS #11 v2.20 amendment 2 */
    
    public static final int KIP_DERIVE = 0x00000510;    
    public static final int KIP_WRAP = 0x00000511;    
    public static final int KIP_MAC = 0x00000512;    
    
    
    /* Camellia is new for PKCS #11 v2.20 amendment 3 */
    
    public static final int CAMELLIA_KEY_GEN = 0x00000550;    
    public static final int CAMELLIA_ECB = 0x00000551;    
    public static final int CAMELLIA_CBC = 0x00000552;    
    public static final int CAMELLIA_MAC = 0x00000553;    
    public static final int CAMELLIA_MAC_GENERAL = 0x00000554;    
    public static final int CAMELLIA_CBC_PAD = 0x00000555;    
    public static final int CAMELLIA_ECB_ENCRYPT_DATA = 0x00000556;    
    public static final int CAMELLIA_CBC_ENCRYPT_DATA = 0x00000557;    
    public static final int CAMELLIA_CTR = 0x00000558;    
    
    
    /* ARIA is new for PKCS #11 v2.20 amendment 3 */
    
    public static final int ARIA_KEY_GEN = 0x00000560;    
    public static final int ARIA_ECB = 0x00000561;    
    public static final int ARIA_CBC = 0x00000562;    
    public static final int ARIA_MAC = 0x00000563;    
    public static final int ARIA_MAC_GENERAL = 0x00000564;    
    public static final int ARIA_CBC_PAD = 0x00000565;    
    public static final int ARIA_ECB_ENCRYPT_DATA = 0x00000566;    
    public static final int ARIA_CBC_ENCRYPT_DATA = 0x00000567;    
    
    
    /* Fortezza mechanisms */
    
    public static final int SKIPJACK_KEY_GEN = 0x00001000;    
    public static final int SKIPJACK_ECB64 = 0x00001001;    
    public static final int SKIPJACK_CBC64 = 0x00001002;    
    public static final int SKIPJACK_OFB64 = 0x00001003;    
    public static final int SKIPJACK_CFB64 = 0x00001004;    
    public static final int SKIPJACK_CFB32 = 0x00001005;    
    public static final int SKIPJACK_CFB16 = 0x00001006;    
    public static final int SKIPJACK_CFB8 = 0x00001007;    
    public static final int SKIPJACK_WRAP = 0x00001008;    
    public static final int SKIPJACK_PRIVATE_WRAP = 0x00001009;    
    public static final int SKIPJACK_RELAYX = 0x0000100a;    
    public static final int KEA_KEY_PAIR_GEN = 0x00001010;    
    public static final int KEA_KEY_DERIVE = 0x00001011;    
    public static final int FORTEZZA_TIMESTAMP = 0x00001020;    
    public static final int BATON_KEY_GEN = 0x00001030;    
    public static final int BATON_ECB128 = 0x00001031;    
    public static final int BATON_ECB96 = 0x00001032;    
    public static final int BATON_CBC128 = 0x00001033;    
    public static final int BATON_COUNTER = 0x00001034;    
    public static final int BATON_SHUFFLE = 0x00001035;    
    public static final int BATON_WRAP = 0x00001036;    
    
    
    /* ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
     * EC_KEY_PAIR_GEN is preferred */
     
    public static final int ECDSA_KEY_PAIR_GEN = 0x00001040;     
    public static final int EC_KEY_PAIR_GEN = 0x00001040;     
     
     
    public static final int ECDSA = 0x00001041;     
    public static final int ECDSA_SHA1 = 0x00001042;     
     
     
     /* ECDH1_DERIVE, ECDH1_COFACTOR_DERIVE, and ECMQV_DERIVE
      * are new for v2.11 */
      
    public static final int ECDH1_DERIVE = 0x00001050;      
    public static final int ECDH1_COFACTOR_DERIVE = 0x00001051;      
    public static final int ECMQV_DERIVE = 0x00001052;      
      
      
    public static final int JUNIPER_KEY_GEN = 0x00001060;      
    public static final int JUNIPER_ECB128 = 0x00001061;      
    public static final int JUNIPER_CBC128 = 0x00001062;      
    public static final int JUNIPER_COUNTER = 0x00001063;      
    public static final int JUNIPER_SHUFFLE = 0x00001064;      
    public static final int JUNIPER_WRAP = 0x00001065;      
    public static final int FASTHASH = 0x00001070;      
      
      
      /* AES_KEY_GEN, AES_ECB, AES_CBC, AES_MAC,
       * AES_MAC_GENERAL, AES_CBC_PAD, DSA_PARAMETER_GEN,
        * DH_PKCS_PARAMETER_GEN, and X9_42_DH_PARAMETER_GEN are
         * new for v2.11 */
         
    public static final int AES_KEY_GEN = 0x00001080;         
    public static final int AES_ECB = 0x00001081;         
    public static final int AES_CBC = 0x00001082;         
    public static final int AES_MAC = 0x00001083;         
    public static final int AES_MAC_GENERAL = 0x00001084;         
    public static final int AES_CBC_PAD = 0x00001085;         
         
         
    /* AES counter mode is new for PKCS #11 v2.20 amendment 3 */
         
    public static final int AES_CTR = 0x00001086;         
         
         
    /* BlowFish and TwoFish are new for v2.20 */
         
    public static final int BLOWFISH_KEY_GEN = 0x00001090;         
    public static final int BLOWFISH_CBC = 0x00001091;         
    public static final int TWOFISH_KEY_GEN = 0x00001092;         
    public static final int TWOFISH_CBC = 0x00001093;         
         
         
    /* xxx_ENCRYPT_DATA mechanisms are new for v2.20 */
         
    public static final int DES_ECB_ENCRYPT_DATA = 0x00001100;         
    public static final int DES_CBC_ENCRYPT_DATA = 0x00001101;         
    public static final int DES3_ECB_ENCRYPT_DATA = 0x00001102;         
    public static final int DES3_CBC_ENCRYPT_DATA = 0x00001103;         
    public static final int AES_ECB_ENCRYPT_DATA = 0x00001104;         
    public static final int AES_CBC_ENCRYPT_DATA = 0x00001105;         
         
         
    public static final int DSA_PARAMETER_GEN = 0x00002000;         
    public static final int DH_PKCS_PARAMETER_GEN = 0x00002001;         
    public static final int X9_42_DH_PARAMETER_GEN = 0x00002002;         
         
         
    public static final int VENDOR_DEFINED = 0x80000000;
             
         
    public Mechanism(NativeLong mechanism)
    {
        this.mechanism = mechanism;
    }

    public Mechanism(int mechanism)
    {
        this.mechanism = new NativeLong(mechanism);
    }

    public NativeLong getMechanism()
    {
        return mechanism;
    }

    public String toString()
    {
        switch (mechanism.intValue())
        {
            case RSA_PKCS_KEY_PAIR_GEN : return "RSA_PKCS_KEY_PAIR_GEN";
            case RSA_PKCS : return "RSA_PKCS";
            case RSA_9796 : return "RSA_9796";
            case RSA_X_509 : return "RSA_X_509";

            case MD2_RSA_PKCS : return "MD2_RSA_PKCS";
            case MD5_RSA_PKCS : return "MD5_RSA_PKCS";
            case SHA1_RSA_PKCS : return "SHA1_RSA_PKCS";

            case RIPEMD128_RSA_PKCS : return "RIPEMD128_RSA_PKCS";
            case RIPEMD160_RSA_PKCS : return "RIPEMD160_RSA_PKCS";
            case RSA_PKCS_OAEP : return "RSA_PKCS_OAEP";

            case RSA_X9_31_KEY_PAIR_GEN : return "RSA_X9_31_KEY_PAIR_GEN";
            case RSA_X9_31 : return "RSA_X9_31";
            
            case SHA1_RSA_X9_31 : return "SHA1_RSA_X9_31";
            case RSA_PKCS_PSS : return "RSA_PKCS_PSS";
            case SHA1_RSA_PKCS_PSS : return "SHA1_RSA_PKCS_PSS";

            case DSA_KEY_PAIR_GEN : return "DSA_KEY_PAIR_GEN";
            case DSA : return "DSA";
            case DSA_SHA1 : return "DSA_SHA1";
            case DH_PKCS_KEY_PAIR_GEN : return "DH_PKCS_KEY_PAIR_GEN";
            case DH_PKCS_DERIVE : return "DH_PKCS_DERIVE";

            case X9_42_DH_KEY_PAIR_GEN : return "X9_42_DH_KEY_PAIR_GEN";
            case X9_42_DH_DERIVE : return "X9_42_DH_DERIVE";
            case X9_42_DH_HYBRID_DERIVE : return "X9_42_DH_HYBRID_DERIVE";
            case X9_42_MQV_DERIVE : return "X9_42_MQV_DERIVE";

            case SHA256_RSA_PKCS : return "SHA256_RSA_PKCS";
            case SHA384_RSA_PKCS : return "SHA384_RSA_PKCS";
            case SHA512_RSA_PKCS : return "SHA512_RSA_PKCS";
            case SHA256_RSA_PKCS_PSS : return "SHA256_RSA_PKCS_PSS";
            case SHA384_RSA_PKCS_PSS : return "SHA384_RSA_PKCS_PSS";
            case SHA512_RSA_PKCS_PSS : return "SHA512_RSA_PKCS_PSS";

            case SHA224_RSA_PKCS : return "SHA224_RSA_PKCS";
            case SHA224_RSA_PKCS_PSS : return "SHA224_RSA_PKCS_PSS";

            case RC2_KEY_GEN : return "RC2_KEY_GEN";
            case RC2_ECB : return "RC2_ECB";
            case RC2_CBC : return "RC2_CBC";
            case RC2_MAC : return "RC2_MAC";

            case RC2_MAC_GENERAL : return "RC2_MAC_GENERAL";
            case RC2_CBC_PAD : return "RC2_CBC_PAD";

            case RC4_KEY_GEN : return "RC4_KEY_GEN";
            case RC4 : return "RC4";

            case DES_KEY_GEN : return "DES_KEY_GEN";
            case DES_ECB : return "DES_ECB";
            case DES_CBC : return "DES_CBC";
            case DES_MAC : return "DES_MAC";
            case DES_MAC_GENERAL : return "DES_MAC_GENERAL";
            case DES_CBC_PAD : return "DES_CBC_PAD";
            case DES2_KEY_GEN : return "DES2_KEY_GEN";
            case DES3_KEY_GEN : return "DES3_KEY_GEN";
            case DES3_ECB : return "DES3_ECB";
            case DES3_CBC : return "DES3_CBC";
            case DES3_MAC : return "DES3_MAC";
            case DES3_MAC_GENERAL : return "DES3_MAC_GENERAL";
            case DES3_CBC_PAD : return "DES3_CBC_PAD";

            case CDMF_KEY_GEN : return "CDMF_KEY_GEN";
            case CDMF_ECB : return "CDMF_ECB";
            case CDMF_CBC : return "CDMF_CBC";
            case CDMF_MAC : return "CDMF_MAC";
            case CDMF_MAC_GENERAL : return "CDMF_MAC_GENERAL";
            case CDMF_CBC_PAD : return "CDMF_CBC_PAD";


        /* the following four DES mechanisms are new for v2.20 */

            case DES_OFB64 : return "DES_OFB64";
            case DES_OFB8 : return "DES_OFB8";
            case DES_CFB64 : return "DES_CFB64";
            case DES_CFB8 : return "DES_CFB8";


            case MD2 : return "MD2";


        /* MD2_HMAC and MD2_HMAC_GENERAL are new for v2.0 */

            case MD2_HMAC : return "MD2_HMAC";
            case MD2_HMAC_GENERAL : return "MD2_HMAC_GENERAL";


            case MD5 : return "MD5";


        /* MD5_HMAC and MD5_HMAC_GENERAL are new for v2.0 */

            case MD5_HMAC : return "MD5_HMAC";
            case MD5_HMAC_GENERAL : return "MD5_HMAC_GENERAL";


            case SHA_1 : return "SHA_1";


        /* SHA_1_HMAC and SHA_1_HMAC_GENERAL are new for v2.0 */

            case SHA_1_HMAC : return "SHA_1_HMAC";
            case SHA_1_HMAC_GENERAL : return "SHA_1_HMAC_GENERAL";


        /* RIPEMD128, RIPEMD128_HMAC,

         * RIPEMD128_HMAC_GENERAL, RIPEMD160, RIPEMD160_HMAC,
         
          * and RIPEMD160_HMAC_GENERAL are new for v2.10 */
          
            case RIPEMD128 : return "RIPEMD128";  
            case RIPEMD128_HMAC : return "RIPEMD128_HMAC";  
            case RIPEMD128_HMAC_GENERAL : return "RIPEMD128_HMAC_GENERAL";  
            case RIPEMD160 : return "RIPEMD160";  
            case RIPEMD160_HMAC : return "RIPEMD160_HMAC";  
            case RIPEMD160_HMAC_GENERAL : return "RIPEMD160_HMAC_GENERAL";  
          
          
          /* SHA256/384/512 are new for v2.20 */
          
            case SHA256 : return "SHA256";  
            case SHA256_HMAC : return "SHA256_HMAC";  
            case SHA256_HMAC_GENERAL : return "SHA256_HMAC_GENERAL";  
          
          
          /* SHA-224 is new for PKCS #11 v2.20 amendment 3 */
          
            case SHA224 : return "SHA224";  
            case SHA224_HMAC : return "SHA224_HMAC";  
            case SHA224_HMAC_GENERAL : return "SHA224_HMAC_GENERAL";  
          
          
            case SHA384 : return "SHA384";  
            case SHA384_HMAC : return "SHA384_HMAC";  
            case SHA384_HMAC_GENERAL : return "SHA384_HMAC_GENERAL";  
            case SHA512 : return "SHA512";  
            case SHA512_HMAC : return "SHA512_HMAC";  
            case SHA512_HMAC_GENERAL : return "SHA512_HMAC_GENERAL";  
          
          
          /* SecurID is new for PKCS #11 v2.20 amendment 1 */
          
            case SECURID_KEY_GEN : return "SECURID_KEY_GEN";  
            case SECURID : return "SECURID";  
          
          
          /* HOTP is new for PKCS #11 v2.20 amendment 1 */
          
            case HOTP_KEY_GEN : return "HOTP_KEY_GEN";  
            case HOTP : return "HOTP";  
          
          
          /* ACTI is new for PKCS #11 v2.20 amendment 1 */
          
            case ACTI : return "ACTI";  
            case ACTI_KEY_GEN : return "ACTI_KEY_GEN";  
          
          
          /* All of the following mechanisms are new for v2.0 */
          
          /* Note that CAST128 and CAST5 are the same algorithm */
          
            case CAST_KEY_GEN : return "CAST_KEY_GEN";  
            case CAST_ECB : return "CAST_ECB";  
            case CAST_CBC : return "CAST_CBC";  
            case CAST_MAC : return "CAST_MAC";  
            case CAST_MAC_GENERAL : return "CAST_MAC_GENERAL";  
            case CAST_CBC_PAD : return "CAST_CBC_PAD";  
            case CAST3_KEY_GEN : return "CAST3_KEY_GEN";  
            case CAST3_ECB : return "CAST3_ECB";  
            case CAST3_CBC : return "CAST3_CBC";  
            case CAST3_MAC : return "CAST3_MAC";  
            case CAST3_MAC_GENERAL : return "CAST3_MAC_GENERAL";  
            case CAST3_CBC_PAD : return "CAST3_CBC_PAD";  
            case CAST128_KEY_GEN : return "CAST128_KEY_GEN";  
            case CAST128_ECB : return "CAST128_ECB";  
            case CAST128_CBC : return "CAST128_CBC";  
            case CAST128_MAC : return "CAST128_MAC";  
            case CAST128_MAC_GENERAL : return "CAST128_MAC_GENERAL";  
            case CAST128_CBC_PAD : return "CAST128_CBC_PAD";  
            case RC5_KEY_GEN : return "RC5_KEY_GEN";  
            case RC5_ECB : return "RC5_ECB";  
            case RC5_CBC : return "RC5_CBC";  
            case RC5_MAC : return "RC5_MAC";  
            case RC5_MAC_GENERAL : return "RC5_MAC_GENERAL";  
            case RC5_CBC_PAD : return "RC5_CBC_PAD";  
            case IDEA_KEY_GEN : return "IDEA_KEY_GEN";  
            case IDEA_ECB : return "IDEA_ECB";  
            case IDEA_CBC : return "IDEA_CBC";  
            case IDEA_MAC : return "IDEA_MAC";  
            case IDEA_MAC_GENERAL : return "IDEA_MAC_GENERAL";  
            case IDEA_CBC_PAD : return "IDEA_CBC_PAD";  
            case GENERIC_SECRET_KEY_GEN : return "GENERIC_SECRET_KEY_GEN";  
            case CONCATENATE_BASE_AND_KEY : return "CONCATENATE_BASE_AND_KEY";  
            case CONCATENATE_BASE_AND_DATA : return "CONCATENATE_BASE_AND_DATA";  
            case CONCATENATE_DATA_AND_BASE : return "CONCATENATE_DATA_AND_BASE";  
            case XOR_BASE_AND_DATA : return "XOR_BASE_AND_DATA";  
            case EXTRACT_KEY_FROM_KEY : return "EXTRACT_KEY_FROM_KEY";  
            case SSL3_PRE_MASTER_KEY_GEN : return "SSL3_PRE_MASTER_KEY_GEN";  
            case SSL3_MASTER_KEY_DERIVE : return "SSL3_MASTER_KEY_DERIVE";  
            case SSL3_KEY_AND_MAC_DERIVE : return "SSL3_KEY_AND_MAC_DERIVE";  
          
          
          /* SSL3_MASTER_KEY_DERIVE_DH, TLS_PRE_MASTER_KEY_GEN,
           * TLS_MASTER_KEY_DERIVE, TLS_KEY_AND_MAC_DERIVE, and
            * TLS_MASTER_KEY_DERIVE_DH are new for v2.11 */
            
            case SSL3_MASTER_KEY_DERIVE_DH : return "SSL3_MASTER_KEY_DERIVE_DH";    
            case TLS_PRE_MASTER_KEY_GEN : return "TLS_PRE_MASTER_KEY_GEN";    
            case TLS_MASTER_KEY_DERIVE : return "TLS_MASTER_KEY_DERIVE";    
            case TLS_KEY_AND_MAC_DERIVE : return "TLS_KEY_AND_MAC_DERIVE";    
            case TLS_MASTER_KEY_DERIVE_DH : return "TLS_MASTER_KEY_DERIVE_DH";    
            
            
            /* TLS_PRF is new for v2.20 */
            
            case TLS_PRF : return "TLS_PRF";    
            
            
            case SSL3_MD5_MAC : return "SSL3_MD5_MAC";    
            case SSL3_SHA1_MAC : return "SSL3_SHA1_MAC";    
            case MD5_KEY_DERIVATION : return "MD5_KEY_DERIVATION";    
            case MD2_KEY_DERIVATION : return "MD2_KEY_DERIVATION";    
            case SHA1_KEY_DERIVATION : return "SHA1_KEY_DERIVATION";    
            
            
            /* SHA256/384/512 are new for v2.20 */
            
            case SHA256_KEY_DERIVATION : return "SHA256_KEY_DERIVATION";    
            case SHA384_KEY_DERIVATION : return "SHA384_KEY_DERIVATION";    
            case SHA512_KEY_DERIVATION : return "SHA512_KEY_DERIVATION";    
            
            
            /* SHA-224 key derivation is new for PKCS #11 v2.20 amendment 3 */
            
            case SHA224_KEY_DERIVATION : return "SHA224_KEY_DERIVATION";    
            
            
            case PBE_MD2_DES_CBC : return "PBE_MD2_DES_CBC";    
            case PBE_MD5_DES_CBC : return "PBE_MD5_DES_CBC";    
            case PBE_MD5_CAST_CBC : return "PBE_MD5_CAST_CBC";    
            case PBE_MD5_CAST3_CBC : return "PBE_MD5_CAST3_CBC";    
            case PBE_MD5_CAST128_CBC : return "PBE_MD5_CAST128_CBC";    
            case PBE_SHA1_CAST128_CBC : return "PBE_SHA1_CAST128_CBC";    
            case PBE_SHA1_RC4_128 : return "PBE_SHA1_RC4_128";    
            case PBE_SHA1_RC4_40 : return "PBE_SHA1_RC4_40";    
            case PBE_SHA1_DES3_EDE_CBC : return "PBE_SHA1_DES3_EDE_CBC";    
            case PBE_SHA1_DES2_EDE_CBC : return "PBE_SHA1_DES2_EDE_CBC";    
            case PBE_SHA1_RC2_128_CBC : return "PBE_SHA1_RC2_128_CBC";    
            case PBE_SHA1_RC2_40_CBC : return "PBE_SHA1_RC2_40_CBC";    
            
            
            /* PKCS5_PBKD2 is new for v2.10 */
            
            case PKCS5_PBKD2 : return "PKCS5_PBKD2";    
            
            
            case PBA_SHA1_WITH_SHA1_HMAC : return "PBA_SHA1_WITH_SHA1_HMAC";    
            
            
            /* WTLS mechanisms are new for v2.20 */
            
            case WTLS_PRE_MASTER_KEY_GEN : return "WTLS_PRE_MASTER_KEY_GEN";    
            case WTLS_MASTER_KEY_DERIVE : return "WTLS_MASTER_KEY_DERIVE";    
            case WTLS_MASTER_KEY_DERIVE_DH_ECC : return "WTLS_MASTER_KEY_DERIVE_DH_ECC";    
            case WTLS_PRF : return "WTLS_PRF";    
            case WTLS_SERVER_KEY_AND_MAC_DERIVE : return "WTLS_SERVER_KEY_AND_MAC_DERIVE";    
            case WTLS_CLIENT_KEY_AND_MAC_DERIVE : return "WTLS_CLIENT_KEY_AND_MAC_DERIVE";    
            
            
            case KEY_WRAP_LYNKS : return "KEY_WRAP_LYNKS";    
            case KEY_WRAP_SET_OAEP : return "KEY_WRAP_SET_OAEP";    
            
            
            /* CMS_SIG is new for v2.20 */
            
            case CMS_SIG : return "CMS_SIG";    
            
            
            /* KIP mechanisms are new for PKCS #11 v2.20 amendment 2 */
            
            case KIP_DERIVE : return "KIP_DERIVE";    
            case KIP_WRAP : return "KIP_WRAP";    
            case KIP_MAC : return "KIP_MAC";    
            
            
            /* Camellia is new for PKCS #11 v2.20 amendment 3 */
            
            case CAMELLIA_KEY_GEN : return "CAMELLIA_KEY_GEN";    
            case CAMELLIA_ECB : return "CAMELLIA_ECB";    
            case CAMELLIA_CBC : return "CAMELLIA_CBC";    
            case CAMELLIA_MAC : return "CAMELLIA_MAC";    
            case CAMELLIA_MAC_GENERAL : return "CAMELLIA_MAC_GENERAL";    
            case CAMELLIA_CBC_PAD : return "CAMELLIA_CBC_PAD";    
            case CAMELLIA_ECB_ENCRYPT_DATA : return "CAMELLIA_ECB_ENCRYPT_DATA";    
            case CAMELLIA_CBC_ENCRYPT_DATA : return "CAMELLIA_CBC_ENCRYPT_DATA";    
            case CAMELLIA_CTR : return "CAMELLIA_CTR";    
            
            
            /* ARIA is new for PKCS #11 v2.20 amendment 3 */
            
            case ARIA_KEY_GEN : return "ARIA_KEY_GEN";    
            case ARIA_ECB : return "ARIA_ECB";    
            case ARIA_CBC : return "ARIA_CBC";    
            case ARIA_MAC : return "ARIA_MAC";    
            case ARIA_MAC_GENERAL : return "ARIA_MAC_GENERAL";    
            case ARIA_CBC_PAD : return "ARIA_CBC_PAD";    
            case ARIA_ECB_ENCRYPT_DATA : return "ARIA_ECB_ENCRYPT_DATA";    
            case ARIA_CBC_ENCRYPT_DATA : return "ARIA_CBC_ENCRYPT_DATA";    
            
            
            /* Fortezza mechanisms */
            
            case SKIPJACK_KEY_GEN : return "SKIPJACK_KEY_GEN";    
            case SKIPJACK_ECB64 : return "SKIPJACK_ECB64";    
            case SKIPJACK_CBC64 : return "SKIPJACK_CBC64";    
            case SKIPJACK_OFB64 : return "SKIPJACK_OFB64";    
            case SKIPJACK_CFB64 : return "SKIPJACK_CFB64";    
            case SKIPJACK_CFB32 : return "SKIPJACK_CFB32";    
            case SKIPJACK_CFB16 : return "SKIPJACK_CFB16";    
            case SKIPJACK_CFB8 : return "SKIPJACK_CFB8";    
            case SKIPJACK_WRAP : return "SKIPJACK_WRAP";    
            case SKIPJACK_PRIVATE_WRAP : return "SKIPJACK_PRIVATE_WRAP";    
            case SKIPJACK_RELAYX : return "SKIPJACK_RELAYX";    
            case KEA_KEY_PAIR_GEN : return "KEA_KEY_PAIR_GEN";    
            case KEA_KEY_DERIVE : return "KEA_KEY_DERIVE";    
            case FORTEZZA_TIMESTAMP : return "FORTEZZA_TIMESTAMP";    
            case BATON_KEY_GEN : return "BATON_KEY_GEN";    
            case BATON_ECB128 : return "BATON_ECB128";    
            case BATON_ECB96 : return "BATON_ECB96";    
            case BATON_CBC128 : return "BATON_CBC128";    
            case BATON_COUNTER : return "BATON_COUNTER";    
            case BATON_SHUFFLE : return "BATON_SHUFFLE";    
            case BATON_WRAP : return "BATON_WRAP";    
            
            
            /* ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
             * EC_KEY_PAIR_GEN is preferred */
             
            case EC_KEY_PAIR_GEN : return "EC_KEY_PAIR_GEN";     
             
             
            case ECDSA : return "ECDSA";     
            case ECDSA_SHA1 : return "ECDSA_SHA1";     
             
             
             /* ECDH1_DERIVE, ECDH1_COFACTOR_DERIVE, and ECMQV_DERIVE
              * are new for v2.11 */
              
            case ECDH1_DERIVE : return "ECDH1_DERIVE";      
            case ECDH1_COFACTOR_DERIVE : return "ECDH1_COFACTOR_DERIVE";      
            case ECMQV_DERIVE : return "ECMQV_DERIVE";      
              
              
            case JUNIPER_KEY_GEN : return "JUNIPER_KEY_GEN";      
            case JUNIPER_ECB128 : return "JUNIPER_ECB128";      
            case JUNIPER_CBC128 : return "JUNIPER_CBC128";      
            case JUNIPER_COUNTER : return "JUNIPER_COUNTER";      
            case JUNIPER_SHUFFLE : return "JUNIPER_SHUFFLE";      
            case JUNIPER_WRAP : return "JUNIPER_WRAP";      
            case FASTHASH : return "FASTHASH";      
              
              
              /* AES_KEY_GEN, AES_ECB, AES_CBC, AES_MAC,
               * AES_MAC_GENERAL, AES_CBC_PAD, DSA_PARAMETER_GEN,
                * DH_PKCS_PARAMETER_GEN, and X9_42_DH_PARAMETER_GEN are
                 * new for v2.11 */
                 
            case AES_KEY_GEN : return "AES_KEY_GEN";         
            case AES_ECB : return "AES_ECB";         
            case AES_CBC : return "AES_CBC";         
            case AES_MAC : return "AES_MAC";         
            case AES_MAC_GENERAL : return "AES_MAC_GENERAL";         
            case AES_CBC_PAD : return "AES_CBC_PAD";         
                 
                 
            /* AES counter mode is new for PKCS #11 v2.20 amendment 3 */
                 
            case AES_CTR : return "AES_CTR";         
                 
                 
            /* BlowFish and TwoFish are new for v2.20 */
                 
            case BLOWFISH_KEY_GEN : return "BLOWFISH_KEY_GEN";         
            case BLOWFISH_CBC : return "BLOWFISH_CBC";         
            case TWOFISH_KEY_GEN : return "TWOFISH_KEY_GEN";         
            case TWOFISH_CBC : return "TWOFISH_CBC";         
                 
                 
            /* xxx_ENCRYPT_DATA mechanisms are new for v2.20 */
                 
            case DES_ECB_ENCRYPT_DATA : return "DES_ECB_ENCRYPT_DATA";         
            case DES_CBC_ENCRYPT_DATA : return "DES_CBC_ENCRYPT_DATA";         
            case DES3_ECB_ENCRYPT_DATA : return "DES3_ECB_ENCRYPT_DATA";         
            case DES3_CBC_ENCRYPT_DATA : return "DES3_CBC_ENCRYPT_DATA";         
            case AES_ECB_ENCRYPT_DATA : return "AES_ECB_ENCRYPT_DATA";         
            case AES_CBC_ENCRYPT_DATA : return "AES_CBC_ENCRYPT_DATA";         
                 
                 
            case DSA_PARAMETER_GEN : return "DSA_PARAMETER_GEN";         
            case DH_PKCS_PARAMETER_GEN : return "DH_PKCS_PARAMETER_GEN";         
            case X9_42_DH_PARAMETER_GEN : return "X9_42_DH_PARAMETER_GEN";         
                 
                 
            case VENDOR_DEFINED : return "VENDOR_DEFINED";


/*            case RSA_PKCS_KEY_PAIR_GEN: return "RSA_PKCS_KEY_PAIR_GEN";
            case RSA_PKCS: return "RSA_PKCS";
            case RSA_9796: return "RSA_9796";
            case RSA_X_509: return "RSA_X_509";
            case DSA_KEY_PAIR_GEN: return "DSA_KEY_PAIR_GEN";
            case DSA: return "DSA";
            case DSA_SHA1: return "DSA_SHA1";
            case DH_PKCS_KEY_PAIR_GEN: return "DH_PKCS_KEY_PAIR_GEN"; 
            case DH_PKCS_DERIVE: return "DH_PKCS_DERIVE"; 
            case DES_KEY_GEN: return "DES_KEY_GEN";
            case DES_ECB: return "DES_ECB";
            case DES_CBC: return "DES_CBC";
            case DES_CBC_PAD: return "DES_CBC_PAD";
            case DES_MAC: return "DES_MAC"; 
            case DES_MAC_GENERAL: return "DES_MAC_GENERAL"; 
            case DES2_KEY_GEN: return "DES2_KEY_GEN";
            case DES3_KEY_GEN: return "DES3_KEY_GEN";
            case DES3_ECB: return "DES3_ECB";
            case DES3_CBC: return "DES3_CBC";
            case DES3_CBC_PAD: return "DES3_CBC_PAD";
            case DES3_MAC: return "DES3_MAC"; 
            case DES3_MAC_GENERAL: return "DES3_MAC_GENERAL"; 
            case AES_KEY_GEN: return "AES_KEY_GEN";
            case AES_ECB: return "AES_ECB";
            case AES_CBC: return "AES_CBC";
            case AES_CBC_PAD: return "AES_CBC_PAD";
            case AES_MAC: return "AES_MAC"; 
            case AES_MAC_GENERAL: return "AES_MAC_GENERAL";  */
        }

        // This should not happen! 
        return "Unknown mechanism";
    }

    public boolean isSymmetric()
    {
        return !(isAsymmetric());
    }

    // TODO where do we use this? This is far to be up-to-date!
    public boolean isAsymmetric()
    {
        switch (mechanism.intValue())
        {
            case RSA_PKCS_KEY_PAIR_GEN:
            case RSA_PKCS:
            case RSA_9796:
            case RSA_X_509:
            case DSA_KEY_PAIR_GEN:
            case DSA:
            case DSA_SHA1:
            case DH_PKCS_KEY_PAIR_GEN:
            case DH_PKCS_DERIVE:
                return true;
        }

        return false;
    }
}
