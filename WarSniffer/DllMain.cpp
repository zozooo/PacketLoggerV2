/* 
* created by zozooo  9/21/2013
* This is a packet logging tool for warhammer online 1.4.8
* In order to run this tool, you must move the PacketLogger folder to warhammer main directory 
* Example : ...\Electronic Arts\Warhammer Online - Age of Reckoning\PacketLogger
*
* List of files/folders needed:
*	file:	ignorelist.txt
*	file:	PacketLogger.exe
*	file:	WarSniffer.dll
*	folder:	logs
*/


#include <windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <time.h>
#include "utils.h"
#include "opcodes.h"
#include "./detours.h"
#pragma comment( lib, "./detours.lib" )


HMODULE dllhandle;
FILE* fp;
char * fileName;
bool ignorelist[0xFF+1];
bool ignoring=false;


using namespace std;



char* createFileName()
{
	time_t rawtime;
  struct tm * timeinfo;
  char buffer [100];

  time (&rawtime);
  timeinfo = localtime (&rawtime);

  strftime (buffer,100,".//PacketLogger//logs//sniff_h%Hm%M.txt",timeinfo);
  return buffer;
}

void dumpBox(unsigned char* packet, unsigned int opcode,int length, bool isFromClient)
{

			fopen_s(&fp,fileName, "ab+");
			char* sname = isFromClient ? "Client" : "Server";
	          fprintf(fp, "\n[%s] packet : (0x%02X) %s  Size = %d \r\n",sname, opcode,opcodeS[opcode], length);
            fprintf(fp, "|------------------------------------------------|----------------|\r\n");
            fprintf(fp, "|00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |0123456789ABCDEF|\r\n");
            fprintf(fp, "|------------------------------------------------|----------------|\r\n");
            int countpos = 0;
            int charcount = 0;
            int charpos = 0;
            int line = 1;

            if (length > 0)
            {
                fprintf(fp, "|");
                for (int count = 0; count < length; count++)
                {
                    if (line == 0) { 
						fprintf(fp, "|"); 
						line = 1; 
					}
					fprintf(fp, "%02X ",packet[count]);
                    countpos++;
                    if (countpos == 16)
                    {
                        fprintf(fp, "|");
                        for (int c = charcount; c < length; c++)
                        {
                            if (((int)packet[charcount] < 32) || ((int)packet[charcount] > 126))
                            {
                                fprintf(fp, ".");
                            }
                            else { 
							fprintf(fp, "%c",packet[charcount]);
							}

                            charcount++;
                            charpos++;
                            if (charpos == 16)
                            {
                                charpos = 0;
                                break;
                            }
                        }
                        if (charcount < length) 
						{ 
							fprintf(fp, "|\r\n"); 
						} else { 
							fprintf(fp, "|"); 
						}
                        countpos = 0;
                        line = 0;
                    }
                }
                if (countpos < 16)
                {
                    for (int k = 0; k < 16 - countpos; k++)
                    { fprintf(fp, "   "); }
                }
                if (charcount < length)
                {
                    fprintf(fp, "|");

                    for (int c = charcount; c < length; c++)
                    {
                        fprintf(fp, ".");
                        charcount++;
                        charpos++;
                    }

                    if (charpos < 16)
                    {
                        for (int j = 0; j < 16 - charpos; j++)
                        { fprintf(fp, " "); }
                    }
                    fprintf(fp, "|");
                }
            }

            fprintf(fp, "\r\n-------------------------------------------------------------------");
			fclose(fp);

}


void ignorePackets()
{
	// from dyox code
	ifstream ignore(".//PacketLogger//ignorelist.txt");
    if(ignore)
    {
        printf("-> loading ignorelist ...\n");
        std::string ligne;
        while ( std::getline( ignore, ligne ) )
        {
            if(!ligne.size())
                continue;

            if(ligne[0] == '/')
                continue;

            for(int i=0;i<0xFF+1;i++)
            {
                if(ligne.compare( opcodeS[i] ) == 0 )
                {
                    ignorelist[i] = true;
                    ignoring=true;
                    printf("ignoring packet [%s] (0x%04X) \n",ligne.c_str(),i);
                    break;
                }
            }
        }

		 printf("\n\n");
	}
}



typedef int(__cdecl* pPacketSent)(int a1, int a2);
pPacketSent oPacketSent;
int __cdecl hkPacketSent(int packetPtr, int length)
{
	unsigned char packetBuf[65535] = {'\0'};
	memcpy(packetBuf,(void*)packetPtr,length+2);
	int opcode = packetBuf[9]; 

	if(!ignorelist[opcode])
	{
	const char * opName = opcodeS[opcode];
	printf("[Sent]     :len=%i\t  (0x%02X)\t %s\n",length+2,opcode,opName);
	dumpBox(packetBuf,opcode,length+2,true);		
	//for(int i = 0; i < length+2;i++)
	//	printf("%02X ",(unsigned char)packetBuf[i]);
	}


	

	return oPacketSent(packetPtr, length);
}


typedef int(__cdecl* pPacketReceived)(void *_this, int a2, int a3, int a4, int a5);
pPacketReceived oPacketReceived;
int __cdecl hkPacketReceived(void *_this, int a2, int a3, int packetPtr, int a5)
{

	DWORD dwLength;

	__asm mov dwLength, ecx

	__asm pushad
	__asm pushfd

	unsigned char packetBuf[65535] = {'\0'};
	memcpy(packetBuf+2,(void*)(packetPtr-0x1),dwLength);  //copy packet
		 // copy length into array
	packetBuf[0]=HIBYTE(LOWORD(dwLength));
	packetBuf[1]=LOBYTE(LOWORD(dwLength));

	int opcode = packetBuf[2]; 

	if(!ignorelist[opcode])
	{
	const char * opName = opcodeS[opcode];
	printf("[Received] :len=%i\t  (0x%02X)\t %s\n",dwLength+3,opcode,opName);
	dumpBox(packetBuf,opcode,dwLength+3,false);
		//for(int i = 0; i < dwLength+3;i++)
		//printf("%02X ",packetBuf[i]);
	}


	__asm popfd
	__asm popad


    return oPacketReceived(_this, a2, a3, packetPtr, a5);
}


void APIENTRY DllThread(LPVOID param)
{

	printf("===================================\n");
    printf("Warhammer: Age of Reckoning 1.4.8\n");
    printf("Packet Logger by zozooo \n");
    printf("Skype: fx@hotmail.com\n");
    printf("===================================\n\n");


	ignorePackets();
	fileName = createFileName();


	DWORD dw_packetSent = 0x004AF104;
	oPacketSent = (pPacketSent)DetourFunction((PBYTE)dw_packetSent, (PBYTE)hkPacketSent);

	DWORD dw_packetReceived = 0x004AE71A;
	oPacketReceived = (pPacketReceived)DetourFunction((PBYTE)dw_packetReceived, (PBYTE)hkPacketReceived);


	

	while(true)
	{
		if(GetAsyncKeyState(VK_END))		
		UnloadDll(dllhandle);

		Sleep(100);
	}
}



BOOL WINAPI DllMain(HINSTANCE hInst, _In_ unsigned _Reason, _In_opt_ void * _Reserved)
{
    if(_Reason == DLL_PROCESS_ATTACH)
    {
		dllhandle = hInst;
		OpenConsole(L"PacketLogger | press [End] to stop");
		DisableThreadLibraryCalls( hInst );
		CreateThread( 0, 0, ( LPTHREAD_START_ROUTINE )DllThread, 0, 0, 0 );

    }
	if(_Reason == DLL_PROCESS_DETACH)
	{

		DetourRemove((PBYTE)oPacketSent,(PBYTE)hkPacketSent);
		DetourRemove((PBYTE)oPacketReceived,(PBYTE)hkPacketReceived);
		
		FreeConsole();
		
	}
    
    return TRUE;
}
