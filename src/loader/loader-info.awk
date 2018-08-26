# Note: This file is included only for targets which have pokedata workaround
/\ypokedata_workaround\y/{pokedata_workaround=strtonum("0x" $2)}
/\y_start\y/{start=strtonum("0x" $2)}
END {
	print "#include <unistd.h>"
	print "const ssize_t offset_to_pokedata_workaround=" (pokedata_workaround-start) ";"
}
