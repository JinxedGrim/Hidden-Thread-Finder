#include "Defs.h"
#define POOL_TAG 'enoB'
KSTART_ROUTINE KstartRoutine;
BOOLEAN APCRAN = FALSE;

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
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);

	DbgPrintEx(0, 0, "[APC] Call Back Called");

	 PKTHREAD_20H2 Kthread = (PKTHREAD_20H2)Apc->Thread;

	 if (Kthread->StackBase && Kthread->StackLimit)
	 {
		 DbgPrintEx(0, 0, "[APC -] Retreived StackBase && StackLimit");
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

	ExFreePoolWithTag(Apc, POOL_TAG);
}

BOOLEAN NmiCallBack(IN PVOID Context, IN BOOLEAN Handled)
{
	PThreadData Ctx = (PThreadData)Context;

	DbgPrintEx(0, 0, "[NMI] Callback Called");

	PETHREAD CurrentThread = (PETHREAD)KeGetCurrentThread();

	if (Ctx->PeThread == CurrentThread)
	{
		DbgPrintEx(0, 0, "[NMI -] Found target thread from NMI");
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
	}

	Ctx->HasDoneNMI = TRUE;

	return TRUE;
}

void KstartRoutine(PVOID Parameter)
{
	PThreadData Ctx = (PThreadData)Parameter;
	DbgPrintEx(0, 0, "Started Thread %d", Ctx->HasCheckedThread);

	PKTHREAD CurrentThread = KeGetCurrentThread();

	PKTHREAD_20H2 KThread = (PKTHREAD_20H2)CurrentThread;
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

	KThread->ApcQueueable = 1;
	KThread->StackBase = StackBase;
	KThread->InitialStack = InitialStack;
	Ctx->CloseThread = TRUE;
	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING reg_path)
{
	UNREFERENCED_PARAMETER(driver_object);
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
	NTSTATUS Stat;
	PVOID NmiDeRegisterAddr = NULL;

	PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, KstartRoutine, &PThread);

	while (!Exit)
	{
		if (PThread.PeThread != NULL && PThread.HasCheckedThread == FALSE)
		{
			DbgPrintEx(0, 0, "Checking Sys Thread State");

			if (((PKTHREAD_20H2)PThread.PeThread)->SystemThread == 0)
			{
				DbgPrintEx(0, 0, "[Query +] Not a system thread");
			}
			else
			{
				DbgPrintEx(0, 0, "[Query -] Is a system thread");
			}
			if (!((PKTHREAD_20H2)PThread.PeThread)->StackBase)
			{
				DbgPrintEx(0, 0, "[Query +] Unable to retrieve StackBase");
			}
			else
			{
				DbgPrintEx(0, 0, "[Query -] Able to retrieve StackBase");
			}

			DbgPrintEx(0, 0, "[APC] Initializing APC");
			PRKAPC ApcToSend = (PRKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), POOL_TAG);
			if (ApcToSend)
			{
				KeInitializeApc(ApcToSend, (PKTHREAD)PThread.PeThread, KAPC_ENVIRONMENT::CurrentApcEnvironment, &APCCallBack, NULL, NULL, KernelMode, NULL);
				if (KeInsertQueueApc(ApcToSend, 0, 0, 0))
				{
					DbgPrintEx(0, 0, "[APC] Queued APC");
				}
				else if(!(((PKTHREAD_20H2)PThread.PeThread)->ApcQueueable))
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
				}
			}
			else
			{
				DbgPrintEx(0, 0, "[APC] Failed To Allocate APC");
				PThread.HasDoneApc = TRUE;
				ExFreePoolWithTag(ApcToSend, POOL_TAG);
			}

			PThread.HasCheckedThread = TRUE;
		}
		if (PThread.HasDoneApc && PThread.HasCheckedThread && PThread.DoNmi == FALSE)
		{
			DbgPrintEx(0, 0, "[NMI] Registering NMI");
			NmiDeRegisterAddr = KeRegisterNmiCallback(NmiCallBack, &PThread);
			if (!NmiDeRegisterAddr)
			{
				DbgPrintEx(0, 0, "[NMI] Failed To Register NMI");
			    Stat = KeDeregisterNmiCallback(NmiDeRegisterAddr);
				NmiDeRegisterAddr = NULL;
				if (Stat != STATUS_SUCCESS)
				{
					DbgPrintEx(0, 0, "Error Deregistering callback");
				}
			}
			else
			{
				ULONG processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
				if (processorCount == 1)
				{
					DbgPrintEx(0, 0, "[NMI] Failed To Register NMI");
					Stat = KeDeregisterNmiCallback(NmiDeRegisterAddr);
					if (Stat != STATUS_SUCCESS)
					{
						DbgPrintEx(0, 0, "Error Deregistering callback");
					}
				}
				else
				{
					KAFFINITY_EX Affinity;
					KeInitializeAffinityEx(&Affinity);
					ULONG processorBitMask = 0;
					for (ULONG i = 0; i < processorCount; ++i)
					{
						KeAddProcessorAffinityEx(&Affinity, i);
					}
					DbgPrintEx(0, 0, "[NMI] Sending NMI");
					HalSendNMI(Affinity);
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

	DbgPrintEx(0, 0, "Unloading");

	ZwClose(ThreadHandle);
	if (NmiDeRegisterAddr != NULL)
	{
		NT_VERIFY(NT_SUCCESS(KeDeregisterNmiCallback(NmiDeRegisterAddr)));
	}

	return STATUS_SUCCESS;
}
