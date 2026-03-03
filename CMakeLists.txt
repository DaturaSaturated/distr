# CMakeList.txt: проект CMake для Sniffer; включите исходный код и определения,
# укажите здесь логику для конкретного проекта.
#

# Добавьте источник в исполняемый файл этого проекта.
add_executable (Sniffer "main.cpp" "sniffer.h" "sniffer.cpp"  "parser.cpp" "parser.h" "tracker.cpp" "tracker.h" "handlers.cpp" "handlers.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET Sniffer PROPERTY CXX_STANDARD 20)
endif()

# Линкуем libpcap
target_link_libraries(Sniffer pcap)

# TODO: Добавьте тесты и целевые объекты, если это необходимо.
