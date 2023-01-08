include_directories(.)

add_executable(
  test

  test.cpp)
target_link_libraries(
  test

  snark
)
target_include_directories(
  test

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(
  test-gadget

  test-gadget.cpp
)
target_link_libraries(
  test-gadget

  snark

  cryptopp
)
target_include_directories(
  test-gadget

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/cryptopp-cmake
)


add_executable(
        test-hash-snark

        test-hash-snark.cpp
        hash-snark.cpp hash-snark.h)
target_link_libraries(
        test-hash-snark

        snark

        cryptopp
)
target_include_directories(
        test-hash-snark

        PUBLIC
        ${DEPENDS_DIR}/libsnark
        ${DEPENDS_DIR}/libsnark/depends/libfqfft
        ${DEPENDS_DIR}/libsnark/depends/libff
        ${DEPENDS_DIR}/cryptopp-cmake
)
