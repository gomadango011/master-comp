check_include_file_cxx(stdint.h HAVE_STDINT_H)
if(HAVE_STDINT_H)
    add_definitions(-DHAVE_STDINT_H)
endif()

set(examples_as_tests_sources)
if(${ENABLE_EXAMPLES})
    set(examples_as_tests_sources
        #test/out-band-WH-examples-test-suite.cc
        )
endif()

build_lib(
    LIBNAME out-band-WH
    SOURCE_FILES model/out-band-WH.cc
                 helper/out-band-WH-helper.cc
    HEADER_FILES model/out-band-WH.h
                 helper/out-band-WH-helper.h
    LIBRARIES_TO_LINK 
        ${libinternet}
        ${libmobility}
        ${libaodv}
    TEST_SOURCES test/out-band-WH-test-suite.cc
                 ${examples_as_tests_sources}
)
