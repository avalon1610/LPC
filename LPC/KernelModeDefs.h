#pragma once
#include "CommonDefs.h"

NTSTATUS NtConnectPort(OUT PHANDLE PortHandle,
					   IN PUNICODE_STRING PortName,
					   IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
					   IN OUT PPORT_VIEW ClientView OPTIONAL,
					   OUT PREMOTE_PORT_VIEW ServerView OPTIONAL,
					   OUT PULONG MaxMessageLength OPTIONAL,
					   IN OUT PVOID ConnectInformation OPTIONAL,
					   IN OUT PULONG ConnectInformationLength OPTIONAL
					   );

