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

/*
 * XSEC
 *
 * OpenSSLCryptoHashHMAC := OpenSSL Implementation of HMAC
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#include <xsec/framework/XSECDefs.hpp>

#if defined (XSEC_HAVE_OPENSSL)

#include <xsec/dsig/DSIGConstants.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoKeyHMAC.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoHashHMAC.hpp>
#include <xsec/enc/OpenSSL/OpenSSLSupport.hpp>

#include <memory.h>

// Constructors/Destructors

OpenSSLCryptoHashHMAC::OpenSSLCryptoHashHMAC(HashType alg) : m_mdLen(0),
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    mp_hctx(&m_hctx_store)
#else
    mp_hctx(HMAC_CTX_new())
#endif
	, m_keyLen(0)
 {

    if (!mp_hctx)
        throw XSECCryptoException(XSECCryptoException::ECError, "OpenSSL::CryptoHashHMAC - cannot allocate contexts");

    // Initialise the digest

    mp_md = OpenSSLDigestAlgorithm<true>::getAlgorithm(alg);

    if(!mp_md) {

        throw XSECCryptoException(XSECCryptoException::MDError,
            "OpenSSL:HashHMAC - Error loading Message Digest"); 
    }

    m_initialised = false;
    m_hashType = alg;

}

const XMLCh* OpenSSLCryptoHashHMAC::getProviderName() const {
	return DSIGConstants::s_unicodeStrPROVOpenSSL;
}

void OpenSSLCryptoHashHMAC::setKey(const XSECCryptoKey *key) {

    // Use this to initialise the HMAC Context

    if (key->getKeyType() != XSECCryptoKey::KEY_HMAC) {

        throw XSECCryptoException(XSECCryptoException::MDError,
            "OpenSSL:HashHMAC - Non HMAC Key passed to OpenSSLHashHMAC");

    }

    m_keyLen = ((XSECCryptoKeyHMAC *) key)->getKey(m_keyBuf);


    HMAC_Init(mp_hctx, 
        m_keyBuf.rawBuffer(),
        m_keyLen,
        mp_md);

    m_initialised = true;

}

OpenSSLCryptoHashHMAC::~OpenSSLCryptoHashHMAC() {

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (m_initialised)
        HMAC_CTX_cleanup(mp_hctx);
#else
    HMAC_CTX_free(mp_hctx);
#endif

}



// Hashing Activities

void OpenSSLCryptoHashHMAC::reset(void) {

    if (m_initialised) {

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        HMAC_CTX_cleanup(mp_hctx);
#endif
        HMAC_Init(mp_hctx, 
            m_keyBuf.rawBuffer(),
            m_keyLen,
            mp_md);

    }

}

void OpenSSLCryptoHashHMAC::hash(unsigned char * data, 
                                 unsigned int length) {

    if (!m_initialised)
        throw XSECCryptoException(XSECCryptoException::MDError,
            "OpenSSL:HashHMAC - hash called prior to setKey");


    HMAC_Update(mp_hctx, data, (int) length);

}

unsigned int OpenSSLCryptoHashHMAC::finish(unsigned char * hash,
                                       unsigned int maxLength) {

    unsigned int retLen;
    
    if(EVP_MD_size(mp_md) > (int) maxLength) {

        throw XSECCryptoException(XSECCryptoException::MemoryError,
            "OpenSSL:HashHMAC - Output buffer not big enough for HMAC");
    }
    HMAC_Final(mp_hctx, hash, &retLen);

    return retLen;

}

// Get information

XSECCryptoHash::HashType OpenSSLCryptoHashHMAC::getHashType(void) const {

    return m_hashType;          // This could be any kind of hash

}

#endif /* XSEC_HAVE_OPENSSL */
