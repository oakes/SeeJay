cmake_minimum_required(VERSION 2.4)

add_executable(seejay main.c crypto.c crypto.h util.c util.h)
target_link_libraries(seejay event)
target_link_libraries(seejay crypto)
