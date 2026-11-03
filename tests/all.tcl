package require tcltest
tcltest::configure -testdir [file dirname [file normalize [info script]]] -singleproc 0 {*}$argv
tcltest::runAllTests
