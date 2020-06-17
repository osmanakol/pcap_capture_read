include C:\Users\osman\Desktop\PcapPlusPlus-19.12\Dist\mk\PcapPlusPlus.mk

# All Target
Debug:
	g++.exe  $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main.cpp
	g++.exe  $(PCAPPP_LIBS_DIR) -static-libgcc -static-libstdc++ -o pcapplusplus.exe main.o $(PCAPPP_LIBS)
# Clean Target
cleanDebug:
	del main.o
	del pcapplusplus.exe
