/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
#if !defined(XSEC_OPENSSL_SUPPORT_H)
#define XSEC_OPENSSL_SUPPORT_H 1

#if defined (XSEC_HAVE_OPENSSL)
#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER > 0x30000000L)
    
#elif (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#endif

#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#if defined (XSEC_OPENSSL_HAVE_EC)
#include <openssl/ecdsa.h>
#endif

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoHash.hpp>

// Our own helper functions
const BIGNUM *DSA_get0_pubkey(const DSA *dsa);
const BIGNUM *DSA_get0_privkey(const DSA *dsa);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
// From OpenSSL 1.1
void DSA_get0_key(const DSA *d,
                  const BIGNUM **pub_key, const BIGNUM **priv_key);
int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key);
void DSA_get0_pqg(const DSA *d,
                  const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp);

#if defined (XSEC_OPENSSL_HAVE_EC)

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);

#endif

DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey);

#define EVP_PKEY_id(_evp_) ((_evp_)->type)
#define EVP_PKEY_get0_EC_KEY(_evp_) ((_evp_)->pkey.ec)
#define EVP_PKEY_get0_RSA(_evp_) ((_evp_)->pkey.rsa)
#define X509_get0_extensions(_x509_) ((_x509_)->cert_info->extensions)

#endif

#define DUP_NON_NULL(_what_) ((_what_)?BN_dup((_what_)):NULL)

/**
 * \brief RAII for EVP_ENCODE_CTX
 *
 * In OpenSSL 1.1 EVP_ENCODE_CTX becomes opaque so we cannot
 * just create one on the stack
 */

class EvpEncodeCtxRAII
{
public:
    EvpEncodeCtxRAII();

    ~EvpEncodeCtxRAII();

    EVP_ENCODE_CTX *of(void);

private:
    EVP_ENCODE_CTX *mp_ctx;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
	((defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x30500000L))
    EVP_ENCODE_CTX mp_ctx_store;
#endif    
};

template <bool EnableMD5>
struct OpenSSLDigestAlgorithm
{
    static constexpr const char *md5 = (EnableMD5) ? "MD5" : "";
    static constexpr const char *algorithm_names[] = { 
        "", 
        "SHA1", 
        md5, 
        "SHA224", 
        "SHA256", 
        "SHA384", 
        "SHA512", 
    };

    static const char *getAlgorithmName(XSECCryptoHash::HashType type)
    {
        return algorithm_names[type];
    }

    static const EVP_MD* getAlgorithm(XSECCryptoHash::HashType type)
    {
        
        const char *algorithm_name = getAlgorithmName(type);
        const EVP_MD *evp_md(nullptr); 
        if(strlen(algorithm_name) > 0)
        {
            evp_md = EVP_get_digestbyname(algorithm_name);
            if (!evp_md) {
                const std::string err = "OpenSSL:Hash - " + std::string(algorithm_name) + " not supported by this version of OpenSSL";
                throw XSECCryptoException(XSECCryptoException::MDError,
                    err.c_str());
            }
        }
        return evp_md;
    }
};

#endif
#endif
