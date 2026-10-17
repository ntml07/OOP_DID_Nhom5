cmake_minimum_required(VERSION 3.16)
project(VerifiableCredential)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IDENTITY_SRC
    src/identity/DID.cpp
    src/identity/VerificationMethod.cpp
    src/identity/DIDDocument.cpp
    src/identity/DIDResolver.cpp
)

set(CREDENTIAL_SRC
    src/credential/CredentialSubject.cpp
    src/credential/CredentialStatus.cpp
    src/credential/VerifiableCredential.cpp
)

set(CRYPTO_SRC
    src/crypto/DigitalSignature.cpp
    src/crypto/RSA.cpp
)

# Demo chương trình chính
add_executable(VerifiableCredential
    main.cpp
    ${IDENTITY_SRC}
    ${CREDENTIAL_SRC}
    src/actors/Holder.cpp
    src/actors/Issuer.cpp
    src/actors/Verifier.cpp
    ${CRYPTO_SRC}
    src/zkp/SchnorrZKP.cpp
)
target_include_directories(VerifiableCredential PRIVATE include)

# Từng file test_* có main() riêng nên mỗi cái một executable
add_executable(test_identity
    tests/test_identity.cpp
    ${IDENTITY_SRC}
)
target_include_directories(test_identity PRIVATE include)

add_executable(test_credential
    tests/test_credential.cpp
    src/identity/DID.cpp
    ${CREDENTIAL_SRC}
    src/crypto/DigitalSignature.cpp
)
target_include_directories(test_credential PRIVATE include)

add_executable(test_crypto
    tests/test_crypto.cpp
    ${CRYPTO_SRC}
)
target_include_directories(test_crypto PRIVATE include)

add_executable(test_actors
    tests/test_actors.cpp
    src/identity/DID.cpp
    ${CREDENTIAL_SRC}
    src/actors/Holder.cpp
    src/actors/Issuer.cpp
    ${CRYPTO_SRC}
)
target_include_directories(test_actors PRIVATE include)

add_executable(test_zkp
    tests/test_zkp.cpp
    src/zkp/SchnorrZKP.cpp
)
target_include_directories(test_zkp PRIVATE include)
