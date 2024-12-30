SHELL=cmd
CXX=g++
CDEFFLAGS=-std=c++20 -Wall -WnoWrite-strings -Wpedantic -Wconversion -fdiagnostics-color=always
CDEBFLAGS=-g -O0 -D _DEBUG
CFLAGS=-O3 -Wl,--strip-all,--build-id=none,--gc-sections -fno-ident -D NDEBUG -static -fno-rtti
LIB=-municode -mwindows -lcomctl32 -lws2_32 -lcrypt32

OBJ=Release
DOBJ=Debug

TARGET=TLSMail

default: debug


MKDIR-Release:
	IF NOT EXIST $(OBJ) mkdir $(OBJ)

MKDIR-Debug:
	IF NOT EXIST $(DOBJ) mkdir $(DOBJ)


OBJS_REL = $(patsubst %.cpp, $(OBJ)/%.o, $(wildcard *.cpp)) $(OBJ)/resource.o

$(OBJ)/resource.o: resource.rc
	windres -i $^ $@ -D NDEBUG

$(OBJ)/%.o: %.cpp
	$(CXX) -c $^ -o $@ $(CDEFFLAGS) $(CFLAGS) -I.


release: MKDIR-Release $(OBJS_REL)
	$(CXX) $(OBJS_REL) -o $(TARGET).exe $(CFLAGS) $(LIB) -I.
	./$(TARGET).exe


OBJS_DEB = $(patsubst %.cpp, $(DOBJ)/%.o, $(wildcard *.cpp)) $(DOBJ)/resource.o

$(DOBJ)/resource.o: resource.rc
	windres -i $^ $@ -D _DEBUG

$(DOBJ)/%.o: %.cpp
	$(CXX) -c $^ -o $@ $(CDEFFLAGS) $(CDEBFLAGS) -I.

debug: MKDIR-Debug $(OBJS_DEB)
	$(CXX) $(OBJS_DEB) -o $(TARGET)-debug.exe $(CDEBFLAGS) $(LIB) -I.

run: debug
	./$(TARGET)-debug.exe

clean:
	del *.exe
	IF EXIST $(OBJ) rd /s /q $(OBJ)
	IF EXIST $(DOBJ) rd /s /q $(DOBJ)

