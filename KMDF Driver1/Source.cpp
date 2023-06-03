#include "Defs.h"
#define POOL_TAG 'enoB'

KSTART_ROUTINE KstartRoutine;
BOOLEAN APCRAN = FALSE;
PVOID NmiDeRegisterAddr = NULL;

typedef struct NmiCallbackInformation_
{
	PETHREAD PeThread = NULL; 
	PVOID StackBase = NULL;
	PVOID InitialStack = NULL;
} NmiCallbackInformation, *PtrNmiCallbackInformation;

typedef struct ThreadData_
{
	PETHREAD PeThread = NULL;
	BOOLEAN CloseThread = FALSE;
	BOOLEAN HasCheckedThread = FALSE;
	BOOLEAN HasDoneApc = FALSE;
	BOOLEAN HasDoneNMI = FALSE;
	BOOLEAN DoNmi = FALSE;
} ThreadData, *PThreadData;

VOID NTAPI APCCallBack(KAPC* Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	// not using these args
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);

	DbgPrintEx(0, 0, "[APC] Call Back Called");

	// Grab thread ptr
	PKTHREAD_20H2 Kthread = (PKTHREAD_20H2)Apc->Thread;

	// if we can grab stackbase or stacklimit thread can be stackwalked
	if (Kthread->StackBase && Kthread->StackLimit)
	{
		DbgPrintEx(0, 0, "[APC -] Retreived StackBase && StackLimit");
		// if it is a system thread we SHOULD attempt a stack walk (note the actual stack walking is beyond the scope of this driver)
		if (Kthread->SystemThread == 1)
		{
			DbgPrintEx(0, 0, "[APC -] IsSystemThread");
		}
		else
		{
			DbgPrintEx(0, 0, "[APC +] IsNotSystemThread");
		}
	}
	else
	{
		DbgPrintEx(0, 0, "[APC +] Unable to retrieve StackBase || StackLimit");
	}

	APCRAN = TRUE;

	// free allocated memory
	ExFreePoolWithTag(Apc, POOL_TAG);
}

BOOLEAN NmiCallBack(IN PVOID Context, IN BOOLEAN Handled)
{
	// Grab our ctx ptr
	PThreadData Ctx = (PThreadData)Context;

	DbgPrintEx(0, 0, "[NMI] Callback Called");

	// Grab current thread struct ptr
	PETHREAD CurrentThread = (PETHREAD)KeGetCurrentThread();

	if (Ctx->PeThread == CurrentThread)
	{
		DbgPrintEx(0, 0, "[NMI -] Found target thread from NMI");
		// cast to extended thread ptr (if we are not on 20H2 -> BSOD)
		PKTHREAD_20H2 PThread = (PKTHREAD_20H2)CurrentThread;
		if (PThread->SystemThread)
			DbgPrintEx(0, 0, "[NMI -] Is System Thread");
		else
			DbgPrintEx(0, 0, "[NMI +] Is Not System Thread");
		if (PThread->StackBase)
			DbgPrintEx(0, 0, "[NMI -] Retrieved Stack Base");
		else
			DbgPrintEx(0, 0, "[NMI +] Unable To Retrieve Stack Base");
		if (PThread->InitialStack)
			DbgPrintEx(0, 0, "[NMI -] Retrieved Initial Stack");
		else
			DbgPrintEx(0, 0, "[NMI +] Unable To Retrieve Initial Stack");
		// retrieve thread context -> rip
	}

	Ctx->HasDoneNMI = TRUE;

	return TRUE;
}

void KstartRoutine(PVOID Parameter)
{
	PThreadData Ctx = (PThreadData)Parameter;
	DbgPrintEx(0, 0, "Started Thread %d", Ctx->HasCheckedThread);

	// grab thread ptr
	PKTHREAD CurrentThread = KeGetCurrentThread();

	// cast to extended thread struct (if we are not on 20H2 -> BSOD)
	PKTHREAD_20H2 KThread = (PKTHREAD_20H2)CurrentThread;

	// attempt to spoof some identifiers of the thread
	PVOID StackBase = KThread->StackBase;
	PVOID InitialStack = KThread->InitialStack;
	KThread->SystemThread = 0;
	KThread->ApcQueueable = 0;
	KThread->StackBase = 0;
	KThread->InitialStack = 0;
	Ctx->PeThread = (PETHREAD)CurrentThread;

	BOOLEAN Exit = FALSE;

	while (!Exit)
	{
		if (Ctx->HasCheckedThread == TRUE && Ctx->HasDoneApc == TRUE && Ctx->HasDoneNMI == TRUE)
		{
			Exit = TRUE;
			DbgPrintEx(0, 0, "Ending Thread");
		}
	}

	// if these are not restored -> BSOD
	KThread->ApcQueueable = 1;
	KThread->StackBase = StackBase;
	KThread->InitialStack = InitialStack;
	Ctx->CloseThread = TRUE;
	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverUnload(PDRIVER_OBJECT driver_object)
{
	UNREFERENCED_PARAMETER(driver_object);
	if (NmiDeRegisterAddr)
	{
		if (KeDeregisterNmiCallback(NmiDeRegisterAddr) != STATUS_SUCCESS)
		{
			DbgPrintEx(0, 0, "Failed to deregister");
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING reg_path)
{
	driver_object->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
	UNREFERENCED_PARAMETER(reg_path);

	DbgPrintEx(0, 0, "Loaded");

	ThreadData PThread;
	PThread.CloseThread = FALSE;
	PThread.PeThread = NULL;
	PThread.HasCheckedThread = FALSE;
	PThread.HasDoneApc = FALSE;
	PThread.HasDoneNMI = FALSE;
	PThread.DoNmi = FALSE;
	HANDLE ThreadHandle;
	BOOLEAN Exit = FALSE;
	NTSTATUS Stat = STATUS_UNSUCCESSFUL;

	Stat = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, KstartRoutine, &PThread);

	if (!NT_SUCCESS(Stat))
	{
		DbgPrintEx(0, 0, "Failed To Register SysThread");
		return STATUS_UNSUCCESSFUL;
	}

	while (!Exit)
	{
		if (PThread.PeThread != NULL && PThread.HasCheckedThread == FALSE)
		{
			DbgPrintEx(0, 0, "Checking Sys Thread State");

			// Check if system thread (if it isnt we are probably not gonna look at it to much) (if we are not on 20H2 -> BSOD)
			if (((PKTHREAD_20H2)PThread.PeThread)->SystemThread == 0)
			{
				DbgPrintEx(0, 0, "[Query +] Not a system thread");
			}
			else
			{
				DbgPrintEx(0, 0, "[Query -] Is a system thread");
			}
			// Check if we can retrieve stackbase (if we are not on 20H2 -> BSOD)
			if (!((PKTHREAD_20H2)PThread.PeThread)->StackBase)
			{
				DbgPrintEx(0, 0, "[Query +] Unable to retrieve StackBase");
			}
			else
			{
				DbgPrintEx(0, 0, "[Query -] Able to retrieve StackBase");
			}

			DbgPrintEx(0, 0, "[APC] Initializing APC");
			// allocate pool for APC
			PRKAPC ApcToSend = (PRKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), POOL_TAG);
			DbgPrintEx(0, 0, "[APC] Apc Address: %p", (PVOID)ApcToSend);
			if (ApcToSend)
			{
				// initialize apc
				KeInitializeApc(ApcToSend, (PKTHREAD)PThread.PeThread, KAPC_ENVIRONMENT::CurrentApcEnvironment, &APCCallBack, NULL, NULL, KernelMode, NULL);
				if (KeInsertQueueApc(ApcToSend, 0, 0, 0))
				{
					DbgPrintEx(0, 0, "[APC] Queued APC");
				}
				else if (!(((PKTHREAD_20H2)PThread.PeThread)->ApcQueueable))
				{
					DbgPrintEx(0, 0, "[APC +] Failed To Queue APC");
					PThread.HasDoneApc = TRUE;
					ExFreePoolWithTag(ApcToSend, POOL_TAG);
				}
				else
				{
					DbgPrintEx(0, 0, "[APC] Failed To Queue APC");
					PThread.HasDoneApc = TRUE;
					ExFreePoolWithTag(ApcToSend, POOL_TAG);
					return STATUS_UNSUCCESSFUL;
				}
			}
			else
			{
				DbgPrintEx(0, 0, "[APC] Failed To Allocate APC");
				PThread.HasDoneApc = TRUE;
				ExFreePoolWithTag(ApcToSend, POOL_TAG);
				return STATUS_UNSUCCESSFUL;
			}

			PThread.HasCheckedThread = TRUE;
		}
		if (PThread.HasDoneApc && PThread.HasCheckedThread && PThread.DoNmi == FALSE)
		{
			DbgPrintEx(0, 0, "[NMI] Registering NMI");
			// register nmi and save addr for deregistering
			NmiDeRegisterAddr = KeRegisterNmiCallback(NmiCallBack, &PThread);
			DbgPrintEx(0, 0, "[NMI] NMI Registered at: %p", (PVOID)NmiDeRegisterAddr);
			if (!NmiDeRegisterAddr)
			{
				DbgPrintEx(0, 0, "[NMI] Failed To Register NMI");
				return STATUS_UNSUCCESSFUL;
			}
			else
			{
				// get processor count (nmi gets sent to all active cores and all threads runnin on said cores)
				ULONG processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
				if (processorCount == 1)
				{
					DbgPrintEx(0, 0, "[NMI] Failed To Register NMI");
					return STATUS_UNSUCCESSFUL;
				}
				else
				{
					KAFFINITY_EX Affinity;
					KeInitializeAffinityEx(&Affinity); // Undoced function 
					// Get core affinity
					ULONG processorBitMask = 0;
					for (ULONG i = 0; i < processorCount; ++i)
					{
						KeAddProcessorAffinityEx(&Affinity, i); // Undoced function 
					}
					DbgPrintEx(0, 0, "[NMI] Sending NMI");
					// send nmi 
					HalSendNMI(Affinity); // Completely undocumented function very hard to find info about this one
				}
			}
			PThread.DoNmi = TRUE;
		}
		if (PThread.CloseThread == TRUE)
		{
			DbgPrintEx(0, 0, "Thread Exited");
			Exit = TRUE;
		}
		if (APCRAN == TRUE)
		{
			PThread.HasDoneApc = TRUE;
		}
	}

	ZwClose(ThreadHandle);
	if (NmiDeRegisterAddr != NULL)
	{
		DbgPrintEx(0, 0, "Deregistering CB");
		if (KeDeregisterNmiCallback(NmiDeRegisterAddr) != STATUS_SUCCESS)
		{
			DbgPrintEx(0, 0, "Failed To Deregister");
			return STATUS_UNSUCCESSFUL;
		}
		else
		{
			NmiDeRegisterAddr = NULL;
		}
	}

	return STATUS_SUCCESS;
}
