cmake_minimum_required( VERSION 3.12 )

project( inspector )

set( HEADER_FILES
        include/cs_magic.h
        include/load_commands.h
        include/macho.h
        include/utils.h
        include/Inspector.h)

add_subdirectory( source )

file( READ cmake/MacOSXFrameworkInfo.plist.in TMP_CONTENT )
file( WRITE  ${CMAKE_CURRENT_BINARY_DIR}/MacOSXFrameworkInfo.plist.in ${TMP_CONTENT} )

if ( BUILD_STATIC )
    add_library( inspector_framework STATIC ${HEADER_FILES} )
    target_link_libraries( inspector_framework PUBLIC inspector_object $<TARGET_PROPERTY:inspector_object,INTERFACE_LINK_LIBRARIES> )
    set_target_properties( inspector_framework
            PROPERTIES
                FRAMEWORK TRUE
                OUTPUT_NAME Inspector
                PUBLIC_HEADER "${HEADER_FILES}"
                MACOSX_FRAMEWORK_IDENTIFIER com.cameronpalmer.Inspector
                MACOSX_FRAMEWORK_SHORT_VERSION_STRING 1.0.0
                MACOSX_FRAMEWORK_INFO_PLIST ${CMAKE_CURRENT_BINARY_DIR}/MacOSXFrameworkInfo.plist.in )
else()
    add_library( inspector_framework SHARED ${HEADER_FILES} )
    target_link_libraries( inspector_framework PUBLIC inspector_object $<TARGET_PROPERTY:inspector_object,INTERFACE_LINK_LIBRARIES> )
    set_target_properties( inspector_framework
            PROPERTIES
                FRAMEWORK TRUE
                OUTPUT_NAME Inspector
                PUBLIC_HEADER "${HEADER_FILES}"
                MACOSX_FRAMEWORK_IDENTIFIER com.cameronpalmer.Inspector
                MACOSX_FRAMEWORK_SHORT_VERSION_STRING 1.0.0
                MACOSX_FRAMEWORK_INFO_PLIST ${CMAKE_CURRENT_BINARY_DIR}/MacOSXFrameworkInfo.plist.in
                BUILD_WITH_INSTALL_NAME_DIR on
                INSTALL_NAME_DIR "@rpath" )
endif()

add_executable( inspector main.c )
target_link_libraries( inspector PRIVATE inspector_framework )