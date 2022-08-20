#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include <nthalext.h>
#include <ntimage.h>
#include <ntdddisk.h>
#pragma comment(lib, "ntoskrnl.lib")

//defintions 

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPreformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPreformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B,

}   SYSTEM_INFORMATION_CLASS, * PSystem_InformationClass;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE 	Section;
	PVOID 	MappedBase;
	PVOID 	ImageBase;
	ULONG 	ImageSize;
	ULONG 	Flags;
	USHORT 	LoadOrderIndex;
	USHORT 	InitOrderIndex;
	USHORT 	LoadCount;
	USHORT 	OffsetToFileName;
	UCHAR 	FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfMods;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	BYTE reserved1[16];
	PVOID reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;

} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void);

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;

} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
	BYTE reserved1[2];
	BYTE BeingDebugged;
	BYTE reserved2[1];
	PVOID reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID reserved4;
	PVOID AtlThunkSListPtr;
	PVOID reserved5;
	ULONG reserved6;
	PVOID reserved7;
	ULONG reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID reserved9[45];
	BYTE reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE reserved11[128];
	PVOID reserved12[1];
	ULONG SessionID;
} PEB, * PPEB;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 ModuleListLoadOrder;
	LIST_ENTRY32 ModuleListMemoryOrder;
	LIST_ENTRY32 ModuleListInitOrder;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _WOW64_PROCESS
{
	PPEB32 Wow64;
} WOW64_PROCESS, * PWOW64_PROCESS;

typedef union _WOW64_APC_CONTEXT
{
	struct
	{
		ULONG Apc32BitContext;
		ULONG Apc32BitRoutine;
	};

	PVOID Apc64BitContext;

} WOW64_APC_CONTEXT, * PWOW64_APC_CONTEXT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE) (IN PVOID NormalContext OPTIONAL, IN PVOID SystemArgument1 OPTIONAL, IN PVOID SystemArgument2 OPTIONAL);

typedef VOID(NTAPI* PKKERNEL_ROUTINE) (IN struct _KAPC* Apc, IN OUT PKNORMAL_ROUTINE* NormalRoutine OPTIONAL, IN OUT PVOID* NormalContext OPTIONAL, IN OUT PVOID* SystemArgument1 OPTIONAL, IN OUT PVOID* SystemArgument2 OPTIONAL);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE) (IN struct _KAPC* Apc);

typedef struct _KNMI_HANDLER_CALLBACK
{
    struct _KNMI_HANDLER_CALLBACK* Next;
    PNMI_CALLBACK Callback;
    PVOID Context;
    PVOID Handle;
} KNMI_HANDLER_CALLBACK, * PKNMI_HANDLER_CALLBACK;

typedef union _KWAIT_STATUS_REGISTER
{
    union
    {
        /* 0x0000 */ unsigned char Flags;
        struct /* bitfield */
        {
            /* 0x0000 */ unsigned char State : 3; /* bit position: 0 */
            /* 0x0000 */ unsigned char Affinity : 1; /* bit position: 3 */
            /* 0x0000 */ unsigned char Priority : 1; /* bit position: 4 */
            /* 0x0000 */ unsigned char Apc : 1; /* bit position: 5 */
            /* 0x0000 */ unsigned char UserApc : 1; /* bit position: 6 */
            /* 0x0000 */ unsigned char Alert : 1; /* bit position: 7 */
        }; /* bitfield */
    }; /* size: 0x0001 */
} KWAIT_STATUS_REGISTER, * PKWAIT_STATUS_REGISTER; /* size: 0x0001 */

typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment
} KAPC_ENVIRONMENT;

typedef struct _KTHREAD_20H2_
{
    /* 0x0000 */ struct _DISPATCHER_HEADER Header;
    /* 0x0018 */ void* SListFaultAddress;
    /* 0x0020 */ unsigned __int64 QuantumTarget;
    /* 0x0028 */ void* InitialStack;
    /* 0x0030 */ void* volatile StackLimit;
    /* 0x0038 */ void* StackBase;
    /* 0x0040 */ unsigned __int64 ThreadLock;
    /* 0x0048 */ volatile unsigned __int64 CycleTime;
    /* 0x0050 */ unsigned long CurrentRunTime;
    /* 0x0054 */ unsigned long ExpectedRunTime;
    /* 0x0058 */ void* KernelStack;
    /* 0x0060 */ struct _XSAVE_FORMAT* StateSaveArea;
    /* 0x0068 */ struct _KSCHEDULING_GROUP* volatile SchedulingGroup;
    /* 0x0070 */ union _KWAIT_STATUS_REGISTER WaitRegister;
    /* 0x0071 */ volatile unsigned char Running;
    /* 0x0072 */ unsigned char Alerted[2];
    union
    {
        struct /* bitfield */
        {
            /* 0x0074 */ unsigned long AutoBoostActive : 1; /* bit position: 0 */
            /* 0x0074 */ unsigned long ReadyTransition : 1; /* bit position: 1 */
            /* 0x0074 */ unsigned long WaitNext : 1; /* bit position: 2 */
            /* 0x0074 */ unsigned long SystemAffinityActive : 1; /* bit position: 3 */
            /* 0x0074 */ unsigned long Alertable : 1; /* bit position: 4 */
            /* 0x0074 */ unsigned long UserStackWalkActive : 1; /* bit position: 5 */
            /* 0x0074 */ unsigned long ApcInterruptRequest : 1; /* bit position: 6 */
            /* 0x0074 */ unsigned long QuantumEndMigrate : 1; /* bit position: 7 */
            /* 0x0074 */ unsigned long UmsDirectedSwitchEnable : 1; /* bit position: 8 */
            /* 0x0074 */ unsigned long TimerActive : 1; /* bit position: 9 */
            /* 0x0074 */ unsigned long SystemThread : 1; /* bit position: 10 */
            /* 0x0074 */ unsigned long ProcessDetachActive : 1; /* bit position: 11 */
            /* 0x0074 */ unsigned long CalloutActive : 1; /* bit position: 12 */
            /* 0x0074 */ unsigned long ScbReadyQueue : 1; /* bit position: 13 */
            /* 0x0074 */ unsigned long ApcQueueable : 1; /* bit position: 14 */
            /* 0x0074 */ unsigned long ReservedStackInUse : 1; /* bit position: 15 */
            /* 0x0074 */ unsigned long UmsPerformingSyscall : 1; /* bit position: 16 */
            /* 0x0074 */ unsigned long TimerSuspended : 1; /* bit position: 17 */
            /* 0x0074 */ unsigned long SuspendedWaitMode : 1; /* bit position: 18 */
            /* 0x0074 */ unsigned long SuspendSchedulerApcWait : 1; /* bit position: 19 */
            /* 0x0074 */ unsigned long CetUserShadowStack : 1; /* bit position: 20 */
            /* 0x0074 */ unsigned long BypassProcessFreeze : 1; /* bit position: 21 */
            /* 0x0074 */ unsigned long Reserved : 10; /* bit position: 22 */
        }; /* bitfield */
        /* 0x0074 */ long MiscFlags;
    }; /* size: 0x0004 */
    union
    {
        struct /* bitfield */
        {
            /* 0x0078 */ unsigned long ThreadFlagsSpare : 2; /* bit position: 0 */
            /* 0x0078 */ unsigned long AutoAlignment : 1; /* bit position: 2 */
            /* 0x0078 */ unsigned long DisableBoost : 1; /* bit position: 3 */
            /* 0x0078 */ unsigned long AlertedByThreadId : 1; /* bit position: 4 */
            /* 0x0078 */ unsigned long QuantumDonation : 1; /* bit position: 5 */
            /* 0x0078 */ unsigned long EnableStackSwap : 1; /* bit position: 6 */
            /* 0x0078 */ unsigned long GuiThread : 1; /* bit position: 7 */
            /* 0x0078 */ unsigned long DisableQuantum : 1; /* bit position: 8 */
            /* 0x0078 */ unsigned long ChargeOnlySchedulingGroup : 1; /* bit position: 9 */
            /* 0x0078 */ unsigned long DeferPreemption : 1; /* bit position: 10 */
            /* 0x0078 */ unsigned long QueueDeferPreemption : 1; /* bit position: 11 */
            /* 0x0078 */ unsigned long ForceDeferSchedule : 1; /* bit position: 12 */
            /* 0x0078 */ unsigned long SharedReadyQueueAffinity : 1; /* bit position: 13 */
            /* 0x0078 */ unsigned long FreezeCount : 1; /* bit position: 14 */
            /* 0x0078 */ unsigned long TerminationApcRequest : 1; /* bit position: 15 */
            /* 0x0078 */ unsigned long AutoBoostEntriesExhausted : 1; /* bit position: 16 */
            /* 0x0078 */ unsigned long KernelStackResident : 1; /* bit position: 17 */
            /* 0x0078 */ unsigned long TerminateRequestReason : 2; /* bit position: 18 */
            /* 0x0078 */ unsigned long ProcessStackCountDecremented : 1; /* bit position: 20 */
            /* 0x0078 */ unsigned long RestrictedGuiThread : 1; /* bit position: 21 */
            /* 0x0078 */ unsigned long VpBackingThread : 1; /* bit position: 22 */
            /* 0x0078 */ unsigned long ThreadFlagsSpare2 : 1; /* bit position: 23 */
            /* 0x0078 */ unsigned long EtwStackTraceApcInserted : 8; /* bit position: 24 */
        }; /* bitfield */
        /* 0x0078 */ volatile long ThreadFlags;
    }; /* size: 0x0004 */
    /* 0x007c */ volatile unsigned char Tag;
    /* 0x007d */ unsigned char SystemHeteroCpuPolicy;
    struct /* bitfield */
    {
        /* 0x007e */ unsigned char UserHeteroCpuPolicy : 7; /* bit position: 0 */
        /* 0x007e */ unsigned char ExplicitSystemHeteroCpuPolicy : 1; /* bit position: 7 */
    }; /* bitfield */
    union
    {
        struct /* bitfield */
        {
            /* 0x007f */ unsigned char RunningNonRetpolineCode : 1; /* bit position: 0 */
            /* 0x007f */ unsigned char SpecCtrlSpare : 7; /* bit position: 1 */
        }; /* bitfield */
        /* 0x007f */ unsigned char SpecCtrl;
    }; /* size: 0x0001 */
    /* 0x0080 */ unsigned long SystemCallNumber;
    /* 0x0084 */ unsigned long ReadyTime;
    /* 0x0088 */ void* FirstArgument;
    /* 0x0090 */ struct _KTRAP_FRAME* TrapFrame;
    union
    {
        /* 0x0098 */ struct _KAPC_STATE ApcState;
        struct
        {
            /* 0x0098 */ unsigned char ApcStateFill[43];
            /* 0x00c3 */ char Priority;
            /* 0x00c4 */ unsigned long UserIdealProcessor;
        }; /* size: 0x0030 */
    }; /* size: 0x0030 */
    /* 0x00c8 */ volatile __int64 WaitStatus;
    /* 0x00d0 */ struct _KWAIT_BLOCK* WaitBlockList;
    union
    {
        /* 0x00d8 */ struct _LIST_ENTRY WaitListEntry;
        /* 0x00d8 */ struct _SINGLE_LIST_ENTRY SwapListEntry;
    }; /* size: 0x0010 */
    /* 0x00e8 */ struct _DISPATCHER_HEADER* volatile Queue;
    /* 0x00f0 */ void* Teb;
    /* 0x00f8 */ unsigned __int64 RelativeTimerBias;
    /* 0x0100 */ struct _KTIMER Timer;
    union
    {
        /* 0x0140 */ struct _KWAIT_BLOCK WaitBlock[4];
        struct
        {
            /* 0x0140 */ unsigned char WaitBlockFill4[20];
            /* 0x0154 */ unsigned long ContextSwitches;
        }; /* size: 0x0018 */
        struct
        {
            /* 0x0140 */ unsigned char WaitBlockFill5[68];
            /* 0x0184 */ volatile unsigned char State;
            /* 0x0185 */ char Spare13;
            /* 0x0186 */ unsigned char WaitIrql;
            /* 0x0187 */ char WaitMode;
        }; /* size: 0x0048 */
        struct
        {
            /* 0x0140 */ unsigned char WaitBlockFill6[116];
            /* 0x01b4 */ unsigned long WaitTime;
        }; /* size: 0x0078 */
        struct
        {
            /* 0x0140 */ unsigned char WaitBlockFill7[164];
            union
            {
                struct
                {
                    /* 0x01e4 */ short KernelApcDisable;
                    /* 0x01e6 */ short SpecialApcDisable;
                }; /* size: 0x0004 */
                /* 0x01e4 */ unsigned long CombinedApcDisable;
            }; /* size: 0x0004 */
        }; /* size: 0x00a8 */
        struct
        {
            /* 0x0140 */ unsigned char WaitBlockFill8[40];
            /* 0x0168 */ struct _KTHREAD_COUNTERS* ThreadCounters;
        }; /* size: 0x0030 */
        struct
        {
            /* 0x0140 */ unsigned char WaitBlockFill9[88];
            /* 0x0198 */ struct _XSTATE_SAVE* XStateSave;
        }; /* size: 0x0060 */
        struct
        {
            /* 0x0140 */ unsigned char WaitBlockFill10[136];
            /* 0x01c8 */ void* volatile Win32Thread;
        }; /* size: 0x0090 */
        struct
        {
            /* 0x0140 */ unsigned char WaitBlockFill11[176];
            /* 0x01f0 */ struct _UMS_CONTROL_BLOCK* Ucb;
            /* 0x01f8 */ struct _KUMS_CONTEXT_HEADER* volatile Uch;
        }; /* size: 0x00c0 */
    }; /* size: 0x00c0 */
    union
    {
        /* 0x0200 */ volatile long ThreadFlags2;
        struct /* bitfield */
        {
            /* 0x0200 */ unsigned long BamQosLevel : 8; /* bit position: 0 */
            /* 0x0200 */ unsigned long ThreadFlags2Reserved : 24; /* bit position: 8 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x0204 */ unsigned long Spare21;
    /* 0x0208 */ struct _LIST_ENTRY QueueListEntry;
    union
    {
        /* 0x0218 */ volatile unsigned long NextProcessor;
        struct /* bitfield */
        {
            /* 0x0218 */ unsigned long NextProcessorNumber : 31; /* bit position: 0 */
            /* 0x0218 */ unsigned long SharedReadyQueue : 1; /* bit position: 31 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x021c */ long QueuePriority;
    /* 0x0220 */ struct _KPROCESS* Process;
    union
    {
        /* 0x0228 */ struct _GROUP_AFFINITY UserAffinity;
        struct
        {
            /* 0x0228 */ unsigned char UserAffinityFill[10];
            /* 0x0232 */ char PreviousMode;
            /* 0x0233 */ char BasePriority;
            union
            {
                /* 0x0234 */ char PriorityDecrement;
                struct /* bitfield */
                {
                    /* 0x0234 */ unsigned char ForegroundBoost : 4; /* bit position: 0 */
                    /* 0x0234 */ unsigned char UnusualBoost : 4; /* bit position: 4 */
                }; /* bitfield */
            }; /* size: 0x0001 */
            /* 0x0235 */ unsigned char Preempted;
            /* 0x0236 */ unsigned char AdjustReason;
            /* 0x0237 */ char AdjustIncrement;
        }; /* size: 0x0010 */
    }; /* size: 0x0010 */
    /* 0x0238 */ unsigned __int64 AffinityVersion;
    union
    {
        /* 0x0240 */ struct _GROUP_AFFINITY Affinity;
        struct
        {
            /* 0x0240 */ unsigned char AffinityFill[10];
            /* 0x024a */ unsigned char ApcStateIndex;
            /* 0x024b */ unsigned char WaitBlockCount;
            /* 0x024c */ unsigned long IdealProcessor;
        }; /* size: 0x0010 */
    }; /* size: 0x0010 */
    /* 0x0250 */ unsigned __int64 NpxState;
    union
    {
        /* 0x0258 */ struct _KAPC_STATE SavedApcState;
        struct
        {
            /* 0x0258 */ unsigned char SavedApcStateFill[43];
            /* 0x0283 */ unsigned char WaitReason;
            /* 0x0284 */ char SuspendCount;
            /* 0x0285 */ char Saturation;
            /* 0x0286 */ unsigned short SListFaultCount;
        }; /* size: 0x0030 */
    }; /* size: 0x0030 */
    union
    {
        /* 0x0288 */ struct _KAPC SchedulerApc;
        struct
        {
            /* 0x0288 */ unsigned char SchedulerApcFill0[1];
            /* 0x0289 */ unsigned char ResourceIndex;
        }; /* size: 0x0002 */
        struct
        {
            /* 0x0288 */ unsigned char SchedulerApcFill1[3];
            /* 0x028b */ unsigned char QuantumReset;
        }; /* size: 0x0004 */
        struct
        {
            /* 0x0288 */ unsigned char SchedulerApcFill2[4];
            /* 0x028c */ unsigned long KernelTime;
        }; /* size: 0x0008 */
        struct
        {
            /* 0x0288 */ unsigned char SchedulerApcFill3[64];
            /* 0x02c8 */ struct _KPRCB* volatile WaitPrcb;
        }; /* size: 0x0048 */
        struct
        {
            /* 0x0288 */ unsigned char SchedulerApcFill4[72];
            /* 0x02d0 */ void* LegoData;
        }; /* size: 0x0050 */
        struct
        {
            /* 0x0288 */ unsigned char SchedulerApcFill5[83];
            /* 0x02db */ unsigned char CallbackNestingLevel;
            /* 0x02dc */ unsigned long UserTime;
        }; /* size: 0x0058 */
    }; /* size: 0x0058 */
    /* 0x02e0 */ struct _KEVENT SuspendEvent;
    /* 0x02f8 */ struct _LIST_ENTRY ThreadListEntry;
    /* 0x0308 */ struct _LIST_ENTRY MutantListHead;
    /* 0x0318 */ unsigned char AbEntrySummary;
    /* 0x0319 */ unsigned char AbWaitEntryCount;
    /* 0x031a */ unsigned char AbAllocationRegionCount;
    /* 0x031b */ char SystemPriority;
    /* 0x031c */ unsigned long SecureThreadCookie;
    /* 0x0320 */ struct _KLOCK_ENTRY* LockEntries;
    /* 0x0328 */ struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;
    /* 0x0330 */ struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;
    /* 0x0338 */ unsigned char PriorityFloorCounts[16];
    /* 0x0348 */ unsigned char PriorityFloorCountsReserved[16];
    /* 0x0358 */ unsigned long PriorityFloorSummary;
    /* 0x035c */ volatile long AbCompletedIoBoostCount;
    /* 0x0360 */ volatile long AbCompletedIoQoSBoostCount;
    /* 0x0364 */ volatile short KeReferenceCount;
    /* 0x0366 */ unsigned char AbOrphanedEntrySummary;
    /* 0x0367 */ unsigned char AbOwnedEntryCount;
    /* 0x0368 */ unsigned long ForegroundLossTime;
    union
    {
        /* 0x0370 */ struct _LIST_ENTRY GlobalForegroundListEntry;
        struct
        {
            /* 0x0370 */ struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;
            /* 0x0378 */ unsigned __int64 InGlobalForegroundList;
        }; /* size: 0x0010 */
    }; /* size: 0x0010 */
    /* 0x0380 */ __int64 ReadOperationCount;
    /* 0x0388 */ __int64 WriteOperationCount;
    /* 0x0390 */ __int64 OtherOperationCount;
    /* 0x0398 */ __int64 ReadTransferCount;
    /* 0x03a0 */ __int64 WriteTransferCount;
    /* 0x03a8 */ __int64 OtherTransferCount;
    /* 0x03b0 */ struct _KSCB* QueuedScb;
    /* 0x03b8 */ volatile unsigned long ThreadTimerDelay;
    union
    {
        /* 0x03bc */ volatile long ThreadFlags3;
        struct /* bitfield */
        {
            /* 0x03bc */ unsigned long ThreadFlags3Reserved : 8; /* bit position: 0 */
            /* 0x03bc */ unsigned long PpmPolicy : 2; /* bit position: 8 */
            /* 0x03bc */ unsigned long ThreadFlags3Reserved2 : 22; /* bit position: 10 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x03c0 */ unsigned __int64 TracingPrivate[1];
    /* 0x03c8 */ void* SchedulerAssist;
    /* 0x03d0 */ void* volatile AbWaitObject;
    /* 0x03d8 */ unsigned long ReservedPreviousReadyTimeValue;
    /* 0x03e0 */ unsigned __int64 KernelWaitTime;
    /* 0x03e8 */ unsigned __int64 UserWaitTime;
    union
    {
        /* 0x03f0 */ struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;
        struct
        {
            /* 0x03f0 */ struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry;
            /* 0x03f8 */ unsigned __int64 InGlobalUpdateVpThreadPriorityList;
        }; /* size: 0x0010 */
    }; /* size: 0x0010 */
    /* 0x0400 */ long SchedulerAssistPriorityFloor;
    /* 0x0404 */ unsigned long Spare28;
    /* 0x0408 */ unsigned __int64 EndPadding[5];
} KTHREAD_20H2, * PKTHREAD_20H2; /* size: 0x0430 */


extern "C" NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(IN PEPROCESS Process);

extern "C" PVOID __fastcall PsDereferenceKernelStack();


extern "C" __declspec(dllimport)
NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG ProtextSize, ULONG NewProtect, PULONG OldProtect);

extern "C" NTKERNELAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

extern "C" NTKERNELAPI
PPEB
PsGetProcessPeb(IN PEPROCESS Process);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

extern "C" NTKERNELAPI VOID NTAPI KeInitializeApc(
    IN PKAPC Apc,
    IN PKTHREAD Thread,
    IN KAPC_ENVIRONMENT ApcStateIndex,
    IN PKKERNEL_ROUTINE KernelRoutine,
    IN PKRUNDOWN_ROUTINE RundownRoutine,
    IN PKNORMAL_ROUTINE NormalRoutine,
    IN KPROCESSOR_MODE ApcMode,
    IN PVOID NormalContext
);

extern "C" NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
    PKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment
);

typedef struct _KAFFINITY_EX
{
    USHORT Count;
    USHORT Size;
    ULONG Reserved;
    KAFFINITY Bitmap[20];
} KAFFINITY_EX, * PKAFFINITY_EX;


extern "C" NTHALAPI VOID FASTCALL HalSendNMI(KAFFINITY_EX Affinity);

extern "C" VOID NTAPI KeInitializeAffinityEx(KAFFINITY_EX* Affinity);

extern "C" VOID NTAPI KeAddProcessorAffinityEx(KAFFINITY_EX* Affinity, ULONG ProcessorBitmask);