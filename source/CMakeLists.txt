set( SOURCE_FILES
        cs_magic.c
        load_commands.c
        macho.c
        utils.c
        )

add_library( inspector_object OBJECT ${SOURCE_FILES} )
target_include_directories( inspector_object PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../include )