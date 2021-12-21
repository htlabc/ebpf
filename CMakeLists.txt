cmake_minimum_required(VERSION 3.17)
project(untitled2 C)

set(CMAKE_C_STANDARD 99)

add_executable(untitled2 main.c xdp_router_ipv4_kern.c simple_get_route.c route.c xdp_redirect_kern.c xdp_redirect_htl_user.c route_long.c xdp_redirect_kern.c)