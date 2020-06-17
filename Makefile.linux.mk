include /usr/local/etc/PcapPlusPlus.mk

# All Target
Debug:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libgcc -static-libstdc++ -std=c++11 -o pcapplusplus main.o $(PCAPPP_LIBS)
# Clean Target
cleanDebug:
	del main.o
	del pcapplusplus
