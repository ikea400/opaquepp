@echo off

cxxbridge src\lib.rs --header > ..\src\opaque-rust.h
cxxbridge src\lib.rs > ..\src\opaque-rust.cpp