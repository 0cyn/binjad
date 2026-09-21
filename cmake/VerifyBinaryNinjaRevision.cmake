function(binjad_read_api_revision api_source_dir output_variable)
    execute_process(
        COMMAND git rev-parse HEAD
        WORKING_DIRECTORY "${api_source_dir}"
        RESULT_VARIABLE git_result
        OUTPUT_VARIABLE api_revision
        ERROR_VARIABLE git_error
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT git_result EQUAL 0)
        message(FATAL_ERROR
            "Cannot derive the Git revision for ${api_source_dir}: ${git_error}")
    endif()

    string(TOLOWER "${api_revision}" api_revision)
    string(LENGTH "${api_revision}" revision_length)
    if(NOT revision_length EQUAL 40 OR NOT api_revision MATCHES "^[0-9a-f]+$")
        message(FATAL_ERROR
            "Git HEAD for ${api_source_dir} is not a full revision: ${api_revision}")
    endif()

    set(${output_variable} "${api_revision}" PARENT_SCOPE)
endfunction()

function(binjad_verify_installed_api_revision install_root expected_revision)
    if(APPLE)
        set(revision_file "${install_root}/Contents/Resources/api_REVISION.txt")
    else()
        set(revision_file "${install_root}/api_REVISION.txt")
    endif()

    if(NOT EXISTS "${revision_file}")
        message(FATAL_ERROR
            "Binary Ninja API revision file not found at ${revision_file}. "
            "BN_INSTALL_DIR must name the installation root.")
    endif()

    file(STRINGS "${revision_file}" revision_lines REGEX "^[0-9a-fA-F]+$")
    list(LENGTH revision_lines revision_count)
    if(revision_count EQUAL 0)
        message(FATAL_ERROR
            "No Git revision was found in Binary Ninja revision file ${revision_file}")
    endif()

    list(GET revision_lines -1 installed_revision)
    string(TOLOWER "${installed_revision}" installed_revision)
    string(LENGTH "${installed_revision}" revision_length)
    if(NOT revision_length EQUAL 40)
        message(FATAL_ERROR
            "Invalid Binary Ninja API revision in ${revision_file}: ${installed_revision}")
    endif()

    if(NOT installed_revision STREQUAL expected_revision)
        message(FATAL_ERROR
            "binaryninja-api revision mismatch: submodule is ${expected_revision}, "
            "but ${revision_file} requires ${installed_revision}")
    endif()

    message(STATUS "Verified Binary Ninja API revision: ${expected_revision}")
endfunction()
