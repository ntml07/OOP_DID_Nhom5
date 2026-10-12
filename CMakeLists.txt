cmake_minimum_required(VERSION 3.16)
project(VerifiableCredential)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(VerifiableCredential
    main.cpp
    src/identity/DID.cpp
    src/identity/VerificationMethod.cpp
    src/identity/DIDDocument.cpp
    src/identity/DIDResolver.cpp
    src/credential/CredentialSubject.cpp
    src/credential/CredentialStatus.cpp
    src/credential/VerifiableCredential.cpp
    src/actors/Holder.cpp
    src/actors/Issuer.cpp
    src/actors/Verifier.cpp
    src/crypto/DigitalSignature.cpp
    src/crypto/RSA.cpp
    src/zkp/SchnorrZKP.cpp
)

target_include_directories(VerifiableCredential PRIVATE include)
