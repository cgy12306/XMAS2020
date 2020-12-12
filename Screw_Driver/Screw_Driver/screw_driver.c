/*
파일을 하나 제공해줌.
1. 파일의 내용을 읽어서 ioctl 코드를 보내서 디펜던시를 만족.

2. 다른 인풋을 통해 모든 조건을 통과시키게 함.

3. 만족된 디펜던시를 이용해서 연산을 통해 outputbuffer로 넘겨줌

dependency : file에서 읽음

string : @_@-Round_aNd_roUnd_@nD_r0uNd 29글자

flag = XMAS{Y0u_@r3_tH3_b35t_dRiv3r} 29글자
hash : 3AE17E0FBB4CD96F7583F8AC6567B50B
*/


#include<ntddk.h>
#include<ntstrsafe.h>
#include "md5.h"
#include<bcrypt.h>

#define DEVICE_NAME L"\\Device\\screw" 
#define DOS_DEVICE_NAME L"\\DosDevices\\screw"
#define IOCTL1    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL2    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL3    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

char dependency[100];
char dep[5][5] = { 0, };
char string[30] = "\x73\x6b\x0c\x6a\x54\x0d\x52\x3f\x0c\x64\x6c\x2e\x65\x4a\x33\x0b\x43\x4e\x40\x26\x7f\x72\x1f\x68\x5b\x63\x34\x03\x3c";

NTSTATUS handle_create(IN PDEVICE_OBJECT deviceObj, IN PIRP pIrp) {
	UNREFERENCED_PARAMETER(deviceObj);
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = 0;
	return 0;
}

NTSTATUS handle_close(IN PDEVICE_OBJECT deviceObj, IN PIRP pIrp) {
	UNREFERENCED_PARAMETER(deviceObj);
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	return 0;
}

void cpy() {
	memcpy(dep[0], dependency + 4, 5);
	memcpy(dep[1], dependency + 9, 5);
	memcpy(dep[2], dependency + 14, 5);
	memcpy(dep[3], dependency + 19, 5);
	memcpy(dep[4], dependency + 24, 5);
	memcpy(dependency, "XMAS", 4);
	DbgPrint("copy complete\n");
}

NTSTATUS solve(IN PIO_STACK_LOCATION iostack, IN PIRP pIrp) {
	SIZE_T inputbufferlength = 0;
	SIZE_T outputbufferlength = 0;
	PCHAR input = NULL;
	PCHAR output = NULL;
	char tmp[30] = { 0, };

	input = pIrp->AssociatedIrp.SystemBuffer;
	output = pIrp->AssociatedIrp.SystemBuffer;
	inputbufferlength = iostack->Parameters.DeviceIoControl.InputBufferLength;
	outputbufferlength = iostack->Parameters.DeviceIoControl.OutputBufferLength;
	DbgPrint("============== %s =============\n", input);
	int x = 0, y = 0, i = 0, j = -1, sw = 1, cnt = 4, size = 5, z = 0;
	DbgPrint("%s", dependency);
	for (i = 0; i < 29; i++) {
		tmp[i] = dependency[28 - i] ^ string[i];
	}
	DbgPrint("%s\n", tmp);
	DbgPrint("%s\n", input);
	if (strcmp(tmp, input)) {
		return 0;
	}

	
	memcpy(input, dependency, 4);
	x = 0, y = 0, i = 0, j = -1, sw = 1, cnt = 4, size = 5, z = 0;
	while (1) {
		for (x = 0; x < size; x++) {
			j += sw;
			DbgPrint("%x %x\n", input[cnt], dep[i][j]);
			input[cnt] = (input[cnt] ^ dep[i][j]) + (char)z;
			cnt++;
			z++;
		}
		size -= 1;
		if (size <= 0) break;
		for (y = 0; y < size; y++) {
			i += sw;
			input[cnt] = (input[cnt] ^ dep[i][j]) + (char)z;
			cnt++;
			z++;
		}
		sw *= -1;
	}
	
	DbgPrint("============== %s ==================\n", input);

	return 0;

}


int hash(IN PIO_STACK_LOCATION iostack, IN PIRP pIrp) {
	SIZE_T inputbufferlength = 0;
	SIZE_T outputbufferlength = 0;
	PCHAR input = NULL;
	PCHAR output = NULL;
	md5_state_t state;
	md5_byte_t  sum[16];

	input = pIrp->AssociatedIrp.SystemBuffer;
	output = pIrp->AssociatedIrp.SystemBuffer;
	inputbufferlength = iostack->Parameters.DeviceIoControl.InputBufferLength;
	outputbufferlength = iostack->Parameters.DeviceIoControl.OutputBufferLength;
	char mmd5[33], hash[100] = "2b962312cb4af11d3773ffd6c848e765";
	int result;
	DbgPrint("============== hash!!!!! ==================\n", input);

	md5_init(&state);
	md5_append(&state, (unsigned char*)input, 29);
	md5_finish(&state, sum);
	httpMD5String(sum, mmd5);
	
	result = strcmp(mmd5, hash);

	DbgPrint("============== %s ==================\n", input);
	DbgPrint("============ %s %s ==============\n", mmd5, hash);

	return result;
}

NTSTATUS deviceIoControl(IN PDEVICE_OBJECT deviceObj, IN PIRP pIrp) {

	PIO_STACK_LOCATION iostack = 0;
	ULONG ioctl;
	SIZE_T inputbufferlength = 0;
	SIZE_T outputbufferlength = 0;
	PCHAR input = NULL;
	PCHAR output = NULL;

	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING uniName;
	HANDLE handle;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK ioStatusBlock;

	int result;

	iostack = IoGetCurrentIrpStackLocation(pIrp);

	UNREFERENCED_PARAMETER(deviceObj);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	ioctl = iostack->Parameters.DeviceIoControl.IoControlCode;
	
	input = pIrp->AssociatedIrp.SystemBuffer;
	output = pIrp->AssociatedIrp.SystemBuffer;
	
	inputbufferlength = iostack->Parameters.DeviceIoControl.InputBufferLength;
	outputbufferlength = iostack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (ioctl) {
	case IOCTL1:
		if (inputbufferlength >= 0x3) {
			solve(iostack, pIrp);
			result = hash(iostack, pIrp);
			if (!result) {
				DbgPrint("=============== output : %s ===============\n", output);
				pIrp->IoStatus.Information = 29;
				pIrp->IoStatus.Status = STATUS_SUCCESS;

				IoCompleteRequest(pIrp, 0);

				return STATUS_SUCCESS;
			}
			else {
				pIrp->IoStatus.Information = 0;
				pIrp->IoStatus.Status = 0;
				IoCompleteRequest(pIrp, 0);
				return STATUS_UNSUCCESSFUL;
			}
		}
		break;

	case IOCTL2:
		RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\file");
		LARGE_INTEGER byteOffset;
		InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		ntstatus = ZwOpenFile(&handle, SYNCHRONIZE | FILE_READ_DATA, &objAttr, &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
		if (NT_SUCCESS(ntstatus)) {
			byteOffset.LowPart = byteOffset.HighPart = 0;
			ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, dependency, 0x30, &byteOffset, NULL);
			dependency[29] = 0;
			ZwClose(handle);
		}
		else {
			pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			pIrp->IoStatus.Information = 0;
			return pIrp->IoStatus.Status;
		}
		break;
	case IOCTL3:
		cpy();
		break;
	default:
		DbgPrint("=============== Wrong ==============");
		break;
	}

	IoCompleteRequest(pIrp, 0);
	return pIrp->IoStatus.Status;
}

void DriverUnload(PDRIVER_OBJECT pDriverObject) {
	UNICODE_STRING dosDeviceName = { 0 };
	RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&dosDeviceName);
	IoDeleteDevice(pDriverObject->DeviceObject);
	DbgPrint("================= Bye Bye~ ====================");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT driverObj, IN PUNICODE_STRING regPath) {
	NTSTATUS ntstatus = 0;
	UNICODE_STRING device = { 0, }, dosdevice = { 0, };
	PDEVICE_OBJECT deviceObj = NULL;

	UNREFERENCED_PARAMETER(regPath);

	RtlInitUnicodeString(&device, DEVICE_NAME);
	RtlInitUnicodeString(&dosdevice, DOS_DEVICE_NAME);

	DbgPrint("================= Welcome~ ====================");

	ntstatus = IoCreateDevice(driverObj, 0, &device, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObj);

	if (!NT_SUCCESS(ntstatus)) {
		DbgPrint("IoCreateDevice Failed");
		IoDeleteDevice(driverObj->DeviceObject);
		return ntstatus;
	}

	driverObj->MajorFunction[0] = handle_create;
	driverObj->MajorFunction[2] = handle_close;
	driverObj->MajorFunction[14] = deviceIoControl;

	driverObj->DriverUnload = DriverUnload;
	deviceObj->Flags |= DO_DIRECT_IO;
	deviceObj->Flags &= ~DO_DEVICE_INITIALIZING;

	ntstatus = IoCreateSymbolicLink(&dosdevice, &device);


	return ntstatus;
}