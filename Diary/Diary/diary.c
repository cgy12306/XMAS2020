#include<ntddk.h>
#include<ntstrsafe.h>
#include<string.h>
#include<stdlib.h>
#define DEVICE_NAME L"\\Device\\diary" 
#define DOS_DEVICE_NAME L"\\DosDevices\\diary"
#define IOCTL1    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL2    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL3    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)


NTSTATUS test(PIO_STACK_LOCATION iostack, PIRP pIrp) {
	UNREFERENCED_PARAMETER(iostack);

	char diary[0x10] = { 0, };
	PCHAR sb;
	INT64 st = 0;
	PIRP pirp = pIrp;

	sb = pIrp->AssociatedIrp.SystemBuffer;
	st = sb[0];
	
	//DbgPrint("%d\n", st);
	if ((INT8)st <= 20) {
		st = st & 0xff;
		DbgPrint("%d %x\n", (size_t)st, st );

		memcpy(diary, sb, st);
	}
	IoCompleteRequest(pirp, 0);

	return STATUS_SUCCESS;
}

NTSTATUS test2(PCHAR sb, SIZE_T size) {
	PCHAR memo = NULL;

	if (size >= 4 && size <= 0x200) {
		memo = ExAllocatePoolWithTag(0, size + 4, 0x434759);
		memcpy(memo, sb, size);	
		DbgPrint("allocation success");
	}
	
	if (memo) {
		ExFreePoolWithTag(memo, 0);
		DbgPrint("free success");
	}
	
	return STATUS_SUCCESS;
}

NTSTATUS read(PIO_STACK_LOCATION iostack, PIRP pIrp) {
	UNREFERENCED_PARAMETER(iostack);
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING uniName;
	HANDLE handle;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK ioStatusBlock;
	char diary[0x10] = { 0, };

	RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\Anna's_diary");
	LARGE_INTEGER byteOffset;
	InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ntstatus = ZwOpenFile(&handle, SYNCHRONIZE | FILE_READ_DATA, &objAttr, &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (NT_SUCCESS(ntstatus)) {
		byteOffset.LowPart = byteOffset.HighPart = 0;
		ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, diary, 0x10, &byteOffset, NULL);
		diary[0xf] = 0;
		DbgPrint("Read diary\n");
		ZwClose(handle);
	}
	else {
		pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		pIrp->IoStatus.Information = 0;
		return 0;
	}
	return 0;
}

NTSTATUS write(PIO_STACK_LOCATION iostack, PIRP pIrp) {
	char diary[0x10];
	HANDLE handle;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING uniName;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK ioStatusBlock;
	PCHAR sb;
	INT64 st = 0;
	
	UNREFERENCED_PARAMETER(iostack);
	handle = 0;
	sb = pIrp->AssociatedIrp.SystemBuffer;
	st = sb[0];
	if ((INT8)st <= 0x10) {
		st = st & 0xff;
		memcpy(diary, sb, st);
	}
	else {
		return 0;
	}
	RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\Anna's_diary");
	InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ntstatus = ZwCreateFile(&handle, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	
	if (NT_SUCCESS(ntstatus)) {
		ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, diary, 0x10, NULL, NULL);
		ZwClose(handle);
		DbgPrint("Write diary");
	}
	else {
		return 0;
	}
	return 0;
}

NTSTATUS dispatch(IN PDEVICE_OBJECT deviceObj, IN PIRP pIrp) {
	
	PIO_STACK_LOCATION iostack = 0;
	ULONG ioctl;
	SIZE_T inputbufferlength = 0;
	SIZE_T outputbufferlength = 0;
	wchar_t *input = NULL;
	PCHAR output = NULL;
	PCHAR sb = NULL;

	iostack = IoGetCurrentIrpStackLocation(pIrp);

	UNREFERENCED_PARAMETER(deviceObj);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	ioctl = iostack->Parameters.DeviceIoControl.IoControlCode;

	input = pIrp->AssociatedIrp.SystemBuffer;
	output = pIrp->AssociatedIrp.SystemBuffer;
	
	inputbufferlength = iostack->Parameters.DeviceIoControl.InputBufferLength;
	outputbufferlength = iostack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (iostack->MajorFunction) {
	case IRP_MJ_CREATE:
		pIrp->IoStatus.Information = 0;
		pIrp->IoStatus.Status = 0;
		break;
	case IRP_MJ_CLOSE:
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		break;
	case IRP_MJ_DEVICE_CONTROL:
		switch (ioctl) {
		case IOCTL1:
			sb = pIrp->AssociatedIrp.SystemBuffer;
			test2(sb, inputbufferlength);
			break;

		case IOCTL2:
			read(iostack, pIrp);
			
			break;
		case IOCTL3:
			write(iostack, pIrp);
			//test(iostack, pIrp);
			break;
		default:
			DbgPrint("=============== Anna woke up ==============");
			break;
		}
	}

	IoCompleteRequest(pIrp, 0);
	return pIrp->IoStatus.Status;
}

void DriverUnload(PDRIVER_OBJECT pDriverObject) {
	UNICODE_STRING dosDeviceName = { 0 };
	RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&dosDeviceName);
	IoDeleteDevice(pDriverObject->DeviceObject);
	DbgPrint("================= Anna's diary close ====================");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT driverObj, IN PUNICODE_STRING regPath) {
	NTSTATUS ntstatus = 0;
	UNICODE_STRING device = { 0, }, dosdevice = { 0, };
	PDEVICE_OBJECT deviceObj = NULL;

	UNREFERENCED_PARAMETER(regPath);

	RtlInitUnicodeString(&device, DEVICE_NAME);
	RtlInitUnicodeString(&dosdevice, DOS_DEVICE_NAME);

	DbgPrint("================= Anna's diary open====================");

	ntstatus = IoCreateDevice(driverObj, 0, &device, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObj);

	if (!NT_SUCCESS(ntstatus)) {
		DbgPrint("IoCreateDevice Failed");
		IoDeleteDevice(driverObj->DeviceObject);
		return ntstatus;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		driverObj->MajorFunction[i] = dispatch;
	}

	driverObj->DriverUnload = DriverUnload;
	deviceObj->Flags |= DO_DIRECT_IO;
	deviceObj->Flags &= ~DO_DEVICE_INITIALIZING;

	ntstatus = IoCreateSymbolicLink(&dosdevice, &device);

	return ntstatus;
}