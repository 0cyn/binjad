if(NOT DEFINED BINJAD_MENU_BAR_BUNDLE OR NOT DEFINED BINJAD_MENU_BAR_ICON)
    message(FATAL_ERROR "menu bar bundle and source icon paths are required")
endif()

set(info "${BINJAD_MENU_BAR_BUNDLE}/Contents/Info.plist")
set(executable "${BINJAD_MENU_BAR_BUNDLE}/Contents/MacOS/binjad-menubar")
set(icon "${BINJAD_MENU_BAR_BUNDLE}/Contents/Resources/menubar.png")
foreach(required IN ITEMS "${info}" "${executable}" "${icon}")
    if(NOT EXISTS "${required}")
        message(FATAL_ERROR "menu bar bundle is missing ${required}")
    endif()
endforeach()

function(binjad_require_plist_value key expected)
    execute_process(
        COMMAND /usr/bin/plutil -extract "${key}" raw -o - "${info}"
        RESULT_VARIABLE result
        OUTPUT_VARIABLE actual
        ERROR_VARIABLE error
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "cannot read ${key} from menu bar Info.plist: ${error}")
    endif()
    if(NOT actual STREQUAL expected)
        message(FATAL_ERROR "menu bar Info.plist ${key} is '${actual}', expected '${expected}'")
    endif()
endfunction()

binjad_require_plist_value(CFBundleIdentifier "me.cynder.binjad.menubar")
binjad_require_plist_value(CFBundleExecutable "binjad-menubar")
binjad_require_plist_value(LSUIElement "true")
binjad_require_plist_value(NSAppTransportSecurity.NSAllowsLocalNetworking "true")

file(SHA256 "${BINJAD_MENU_BAR_ICON}" source_icon_hash)
file(SHA256 "${icon}" bundled_icon_hash)
if(NOT source_icon_hash STREQUAL bundled_icon_hash)
    message(FATAL_ERROR "bundled menu bar icon differs from resources/menubar.png")
endif()

execute_process(
    COMMAND /usr/bin/codesign --verify --strict --verbose=2 "${BINJAD_MENU_BAR_BUNDLE}"
    RESULT_VARIABLE signature_result
    OUTPUT_VARIABLE signature_output
    ERROR_VARIABLE signature_error)
if(NOT signature_result EQUAL 0)
    message(FATAL_ERROR
        "menu bar application has an invalid ad hoc signature: "
        "${signature_output}${signature_error}")
endif()
