option(WITH_GSSAPI "Build with GSSAPI support" ON)
option(WITH_ZLIB "Build with ZLIB support" ON)
option(WITH_SFTP "Build with SFTP support" ON)
option(WITH_SERVER "Build with SSH server support" ON)
option(WITH_DEBUG_CRYPTO "Build with crypto debug output" OFF)
option(WITH_DEBUG_PACKET "Build with packet debug output" OFF)
option(WITH_DEBUG_CALLTRACE "Build with calltrace debug output" ON)
option(WITH_DSA "Build with DSA" OFF)
option(WITH_GCRYPT "Compile against libgcrypt" OFF)
option(WITH_MBEDTLS "Compile against libmbedtls" OFF)
option(WITH_BLOWFISH_CIPHER "Compile with blowfish support" OFF)
option(WITH_PCAP "Compile with Pcap generation support" ON)
option(WITH_INTERNAL_DOC "Compile doxygen internal documentation" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(WITH_PKCS11_URI "Build with PKCS#11 URI support" OFF)
option(UNIT_TESTING "Build with unit tests" OFF)
option(CLIENT_TESTING "Build with client tests; requires openssh" OFF)
option(SERVER_TESTING "Build with server tests; requires openssh and dropbear" OFF)
option(WITH_BENCHMARKS "Build benchmarks tools" OFF)
option(WITH_EXAMPLES "Build examples" ON)
option(WITH_NACL "Build with libnacl (curve25519)" ON)
option(WITH_FIDO "Build with FIDO" ON)
option(WITH_SYMBOL_VERSIONING "Build with symbol versioning" ON)
option(WITH_ABI_BREAK "Allow ABI break" OFF)
option(WITH_GEX "Enable DH Group exchange mechanisms" ON)
option(WITH_INSECURE_NONE "Enable insecure none cipher and MAC algorithms (not suitable for production!)" OFF)
option(FUZZ_TESTING "Build with fuzzer for the server and client (automatically enables none cipher!)" OFF)
option(PICKY_DEVELOPER "Build with picky developer flags" OFF)

if (WITH_ZLIB)
    set(WITH_LIBZ ON)
else (WITH_ZLIB)
    set(WITH_LIBZ OFF)
endif (WITH_ZLIB)

if (WITH_BENCHMARKS)
  set(UNIT_TESTING ON)
  set(CLIENT_TESTING ON)
endif()

if (UNIT_TESTING OR CLIENT_TESTING OR SERVER_TESTING)
  set(BUILD_STATIC_LIB ON)
endif()

if (WITH_NACL)
  set(WITH_NACL ON)
endif (WITH_NACL)

if (WITH_ABI_BREAK)
  set(WITH_SYMBOL_VERSIONING ON)
endif (WITH_ABI_BREAK)

if (NOT GLOBAL_BIND_CONFIG)
  set(GLOBAL_BIND_CONFIG "/etc/ssh/libssh_server_config")
endif (NOT GLOBAL_BIND_CONFIG)

if (NOT GLOBAL_CLIENT_CONFIG)
  set(GLOBAL_CLIENT_CONFIG "/etc/ssh/ssh_config")
endif (NOT GLOBAL_CLIENT_CONFIG)

if (FUZZ_TESTING)
  set(WITH_INSECURE_NONE ON)
endif (FUZZ_TESTING)
