cmake_minimum_required(VERSION 3.16)
project(VerifiableCredential)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Main block: shared source groups for app + tests
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

set(ACTORS_SRC
    src/actors/Holder.cpp
    src/actors/Issuer.cpp
    src/actors/Verifier.cpp
)

set(ZKP_SRC
    src/zkp/SchnorrZKP.cpp
)

# Main block: main demo executable
add_executable(VerifiableCredential
    main.cpp
    ${IDENTITY_SRC}
    ${CREDENTIAL_SRC}
    ${ACTORS_SRC}
    ${CRYPTO_SRC}
    ${ZKP_SRC}
)
target_include_directories(VerifiableCredential PRIVATE include)

# Main block: identity module tests
add_executable(test_identity
    tests/test_identity.cpp
    ${IDENTITY_SRC}
)
target_include_directories(test_identity PRIVATE include)

# Main block: credential module tests
add_executable(test_credential
    tests/test_credential.cpp
    src/identity/DID.cpp
    ${CREDENTIAL_SRC}
    src/crypto/DigitalSignature.cpp
)
target_include_directories(test_credential PRIVATE include)

# Main block: crypto module tests
add_executable(test_crypto
    tests/test_crypto.cpp
    ${CRYPTO_SRC}
)
target_include_directories(test_crypto PRIVATE include)

# Main block: actors tests (Holder / Issuer / Verifier + ZKP)
add_executable(test_actors
    tests/test_actors.cpp
    ${IDENTITY_SRC}
    ${CREDENTIAL_SRC}
    ${ACTORS_SRC}
    ${CRYPTO_SRC}
    ${ZKP_SRC}
)
target_include_directories(test_actors PRIVATE include)

# Main block: ZKP module tests
add_executable(test_zkp
    tests/test_zkp.cpp
    ${ZKP_SRC}
)
target_include_directories(test_zkp PRIVATE include)

# Main block: end-to-end integration tests
add_executable(test_integration
    tests/test_integration.cpp
    ${IDENTITY_SRC}
    ${CREDENTIAL_SRC}
    ${ACTORS_SRC}
    ${CRYPTO_SRC}
    ${ZKP_SRC}
)
target_include_directories(test_integration PRIVATE include)
