/*
 * Copyright (c) 2014 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * OvsTunnel.c
 *  WFP Classified callback function and Action code for injecting a packet to the vswitch
 */

#include "precomp.h"

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union
#include <fwpsk.h>
#pragma warning(pop)

#pragma warning( push )
#pragma warning( disable:4127 )

#include <fwpmk.h>
#include "Tunnel.h"
#include "Switch.h"
#include "Vport.h"
#include "Event.h"
#include "User.h"
#include "Vxlan.h"
#include "Gre.h"
#include "PacketIO.h"
#include "NetProto.h"
#include "Flow.h"
#include "Actions.h"
#include <fwpsk.h>

extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

static NTSTATUS
OvsInjectPacketThroughActions(PNET_BUFFER_LIST pNbl,
                              OVS_TUNNEL_PENDED_PACKET *packet);

static NTSTATUS
OvsInjectGrePacketThroughActions(PNET_BUFFER_LIST pNbl,
                                 OVS_TUNNEL_PENDED_PACKET *packet);

VOID OvsAcquireDatapathRead(OVS_DATAPATH *datapath,
                            LOCK_STATE_EX *lockState,
                            BOOLEAN dispatch);
VOID OvsAcquireDatapathWrite(OVS_DATAPATH *datapath,
                             LOCK_STATE_EX *lockState,
                             BOOLEAN dispatch);
VOID OvsReleaseDatapath(OVS_DATAPATH *datapath,
                        LOCK_STATE_EX *lockState);


NTSTATUS
OvsTunnelNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                const GUID *filterKey,
                const FWPS_FILTER *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

static NTSTATUS
OvsTunnelAnalyzePacket(OVS_TUNNEL_PENDED_PACKET *packet)
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 packetLength = 0;
    ULONG bytesCopied = 0;
    NET_BUFFER_LIST *copiedNBL = NULL;
    NET_BUFFER *netBuffer;
    NDIS_STATUS ndisStatus;

    /*
     * For inbound net buffer list, we can assume it contains only one
     * net buffer (unless it was an re-assembeled fragments). in both cases
     * the first net buffer should include all headers, we assert if the retreat fails
     */
    netBuffer = NET_BUFFER_LIST_FIRST_NB(packet->netBufferList);

    /* Drop the packet from the host stack */
    packet->classifyOut->actionType = FWP_ACTION_BLOCK;
    packet->classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    /* Adjust the net buffer list offset to the start of the IP header */
    ndisStatus = NdisRetreatNetBufferDataStart(netBuffer,
                                               packet->ipHeaderSize +
                                               packet->transportHeaderSize,
                                               0, NULL);
    ASSERT(ndisStatus == NDIS_STATUS_SUCCESS);

    /* Single NBL element for WFP */
    ASSERT(packet->netBufferList->Next == NULL);

    /* Note that the copy will inherit the original net buffer list's offset */
    packetLength = NET_BUFFER_DATA_LENGTH(netBuffer);
    copiedNBL = OvsAllocateVariableSizeNBL(gOvsSwitchContext, packetLength,
                                           OVS_DEFAULT_HEADROOM_SIZE);

    if (copiedNBL == NULL) {
        goto analyzeDone;
    }

    status = NdisCopyFromNetBufferToNetBuffer(NET_BUFFER_LIST_FIRST_NB(copiedNBL),
                                              0, packetLength,
                                              netBuffer, 0, &bytesCopied);
    if (status != NDIS_STATUS_SUCCESS || packetLength != bytesCopied) {
        goto analyzeFreeNBL;
    }

    status = OvsInjectGrePacketThroughActions(copiedNBL,
                                              packet);
    goto analyzeDone;

    /* Undo the adjustment on the original net buffer list */
analyzeFreeNBL:
    OvsCompleteNBL(gOvsSwitchContext, copiedNBL, TRUE);
analyzeDone:
    NdisAdvanceNetBufferDataStart(netBuffer,
                                  packet->transportHeaderSize + packet->ipHeaderSize,
                                  FALSE,
                                  NULL);
    return status;
}

#define LOG(Format, ...)                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, #Format "\n", __VA_ARGS__ + 0 ); // add '+ 0' in case we only have just a string to print :)
#pragma warning(disable:4100)
extern HANDLE gTransportInjectHandle;
extern HANDLE gNetworkInjectHandle;
extern HANDLE gL2InjectHandle;
void OvsIpSecInjectComplete2(
   _Inout_ void* context,
   _Inout_ NET_BUFFER_LIST* netBufferList,
   _In_ BOOLEAN dispatchLevel
   )
{
   UNREFERENCED_PARAMETER(context);
   UNREFERENCED_PARAMETER(netBufferList);
   UNREFERENCED_PARAMETER(dispatchLevel);

   if (!NT_SUCCESS(netBufferList->Status)) {
       LOG("Injection status: 0x%08X", netBufferList->Status);
       FwpsFreeNetBufferList(netBufferList);
   }

}

_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
_Success_(return != 0)
FWP_VALUE* OvsValueGetFromIncomingValues(_In_ const FWPS_INCOMING_VALUES* pClassifyValues,
                                                     _In_ const GUID* pConditionKey)
{
   NT_ASSERT(pClassifyValues);
   NT_ASSERT(pConditionKey);

   FWP_VALUE* pValue = 0;

   switch(pClassifyValues->layerId)
   {
      case FWPS_LAYER_INBOUND_IPPACKET_V4:
      case FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD:
      case FWPS_LAYER_INBOUND_IPPACKET_V6:
      case FWPS_LAYER_INBOUND_IPPACKET_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_TUNNEL_TYPE].value);

         break;
      }
      case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
      case FWPS_LAYER_OUTBOUND_IPPACKET_V4_DISCARD:
      case FWPS_LAYER_OUTBOUND_IPPACKET_V6:
      case FWPS_LAYER_OUTBOUND_IPPACKET_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_TUNNEL_TYPE].value);

         break;
      }
      case FWPS_LAYER_IPFORWARD_V4:
      case FWPS_LAYER_IPFORWARD_V4_DISCARD:
      case FWPS_LAYER_IPFORWARD_V6:
      case FWPS_LAYER_IPFORWARD_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_SOURCE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_IP_SOURCE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_IP_DESTINATION_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_IP_DESTINATION_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_FORWARD_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_IP_FORWARD_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_SOURCE_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_SOURCE_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SOURCE_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_SOURCE_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_DESTINATION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_DESTINATION_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_DESTINATION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_DESTINATION_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_FLAGS].value);

#if(NTDDI_VERSION >= NTDDI_WIN7)

         else if(pConditionKey == &FWPM_CONDITION_IP_PHYSICAL_ARRIVAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_IP_PHYSICAL_ARRIVAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_INTERFACE_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_ARRIVAL_INTERFACE_PROFILE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PHYSICAL_NEXTHOP_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_IP_PHYSICAL_NEXTHOP_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_INTERFACE_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_IPFORWARD_V4_NEXTHOP_INTERFACE_PROFILE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN7)

         break;
      }
      case FWPS_LAYER_INBOUND_TRANSPORT_V4:
      case FWPS_LAYER_INBOUND_TRANSPORT_V4_DISCARD:
      case FWPS_LAYER_INBOUND_TRANSPORT_V6:
      case FWPS_LAYER_INBOUND_TRANSPORT_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_TUNNEL_TYPE].value);

#if(NTDDI_VERSION >= NTDDI_WIN7)

         else if(pConditionKey == &FWPM_CONDITION_CURRENT_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_PROFILE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN7)

         break;
      }
      case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
      case FWPS_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD:
      case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
      case FWPS_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_DESTINATION_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_TUNNEL_TYPE].value);

#if(NTDDI_VERSION >= NTDDI_WIN7)

         else if(pConditionKey == &FWPM_CONDITION_CURRENT_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_PROFILE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN7)

         break;
      }
      case FWPS_LAYER_STREAM_V4:
      case FWPS_LAYER_STREAM_V4_DISCARD:
      case FWPS_LAYER_STREAM_V6:
      case FWPS_LAYER_STREAM_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_DIRECTION)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_DIRECTION].value);

#if(NTDDI_VERSION >= NTDDI_VISTASP1)

         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_FLAGS].value);

#endif /// (NTDDI_VERSION >= NTDDI_VISTASP1)

         break;
      }
      case FWPS_LAYER_DATAGRAM_DATA_V4:
      case FWPS_LAYER_DATAGRAM_DATA_V4_DISCARD:
      case FWPS_LAYER_DATAGRAM_DATA_V6:
      case FWPS_LAYER_DATAGRAM_DATA_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_DIRECTION)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_TUNNEL_TYPE].value);

         break;
      }
      case FWPS_LAYER_INBOUND_ICMP_ERROR_V4:
      case FWPS_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD:
      case FWPS_LAYER_INBOUND_ICMP_ERROR_V6:
      case FWPS_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_EMBEDDED_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_EMBEDDED_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_EMBEDDED_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_EMBEDDED_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_EMBEDDED_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_EMBEDDED_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_EMBEDDED_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_EMBEDDED_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_EMBEDDED_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_EMBEDDED_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_ICMP_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_ICMP_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ICMP_CODE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_ICMP_CODE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_TUNNEL_TYPE].value);

#if(NTDDI_VERSION >= NTDDI_VISTASP1)

         else if(pConditionKey == &FWPM_CONDITION_IP_ARRIVAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_IP_ARRIVAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_ARRIVAL_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_ARRIVAL_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_ARRIVAL_TUNNEL_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_FLAGS].value);

#if(NTDDI_VERSION >= NTDDI_WIN7)

         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_INTERFACE_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_ARRIVAL_INTERFACE_PROFILE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_ICMP_ERROR_V4_INTERFACE_QUARANTINE_EPOCH].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN7)
#endif /// (NTDDI_VERSION >= NTDDI_VISTASP1)

         break;
      }
      case FWPS_LAYER_OUTBOUND_ICMP_ERROR_V4:
      case FWPS_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD:
      case FWPS_LAYER_OUTBOUND_ICMP_ERROR_V6:
      case FWPS_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_ICMP_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_ICMP_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ICMP_CODE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_ICMP_CODE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_TUNNEL_TYPE].value);

#if(NTDDI_VERSION >= NTDDI_VISTASP1)

         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_FLAGS].value);

#if(NTDDI_VERSION >= NTDDI_WIN7)

         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_INTERFACE_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_NEXTHOP_INTERFACE_PROFILE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_ICMP_ERROR_V4_INTERFACE_QUARANTINE_EPOCH].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN7)
#endif /// (NTDDI_VERSION >= NTDDI_VISTASP1)

         break;
      }
      case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4:
      case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD:
      case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6:
      case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_PROMISCUOUS_MODE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_PROMISCUOUS_MODE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_TUNNEL_TYPE].value);

#if(NTDDI_VERSION >= NTDDI_WIN7)

         else if(pConditionKey == &FWPM_CONDITION_LOCAL_INTERFACE_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_LOCAL_INTERFACE_PROFILE_ID].value);

#if(NTDDI_VERSION >= NTDDI_WIN8)

         else if(pConditionKey == &FWPM_CONDITION_ALE_PACKAGE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_ALE_PACKAGE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)
#endif /// (NTDDI_VERSION >= NTDDI_WIN7)

         break;
      }
      case FWPS_LAYER_ALE_AUTH_LISTEN_V4:
      case FWPS_LAYER_ALE_AUTH_LISTEN_V4_DISCARD:
      case FWPS_LAYER_ALE_AUTH_LISTEN_V6:
      case FWPS_LAYER_ALE_AUTH_LISTEN_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_TUNNEL_TYPE].value);

#if(NTDDI_VERSION >= NTDDI_WIN7)

         else if(pConditionKey == &FWPM_CONDITION_LOCAL_INTERFACE_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_LOCAL_INTERFACE_PROFILE_ID].value);

#if(NTDDI_VERSION >= NTDDI_WIN8)

         else if(pConditionKey == &FWPM_CONDITION_ALE_PACKAGE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_LISTEN_V4_ALE_PACKAGE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)
#endif /// (NTDDI_VERSION >= NTDDI_WIN7)

         break;
      }
      case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
      case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD:
      case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
      case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_REMOTE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_REMOTE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_REMOTE_MACHINE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_REMOTE_MACHINE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_SIO_FIREWALL_SYSTEM_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SIO_FIREWALL_SYSTEM_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_NAP_CONTEXT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NAP_CONTEXT].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_TUNNEL_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SUB_INTERFACE_INDEX].value);

#if(NTDDI_VERSION >= NTDDI_VISTASP1)

         else if(pConditionKey == &FWPM_CONDITION_IP_ARRIVAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_ARRIVAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ARRIVAL_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ARRIVAL_TUNNEL_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ARRIVAL_INTERFACE_INDEX].value);

#if(NTDDI_VERSION >= NTDDI_WIN7)

         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NEXTHOP_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_NEXTHOP_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_NEXTHOP_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NEXTHOP_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NEXTHOP_TUNNEL_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_NEXTHOP_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_ORIGINAL_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ORIGINAL_PROFILE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_CURRENT_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_CURRENT_PROFILE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_REAUTHORIZE_REASON)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_REAUTHORIZE_REASON].value);
         else if(pConditionKey == &FWPM_CONDITION_ORIGINAL_ICMP_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ORIGINAL_ICMP_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_QUARANTINE_EPOCH].value);

#if(NTDDI_VERSION >= NTDDI_WIN8)

         else if(pConditionKey == &FWPM_CONDITION_ALE_PACKAGE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_PACKAGE_ID].value);


#endif /// (NTDDI_VERSION >= NTDDI_WIN8)
#endif /// (NTDDI_VERSION >= NTDDI_WIN7)
#endif /// (NTDDI_VERSION >= NTDDI_VISTASP1)

         break;
      }
      case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
      case FWPS_LAYER_ALE_AUTH_CONNECT_V4_DISCARD:
      case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
      case FWPS_LAYER_ALE_AUTH_CONNECT_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_REMOTE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_REMOTE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_REMOTE_MACHINE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_REMOTE_MACHINE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_DESTINATION_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_TUNNEL_TYPE].value);

#if(NTDDI_VERSION >= NTDDI_VISTASP1)

         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_SUB_INTERFACE_INDEX].value);

#if(NTDDI_VERSION >= NTDDI_WIN7)

         else if(pConditionKey == &FWPM_CONDITION_IP_ARRIVAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_ARRIVAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ARRIVAL_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ARRIVAL_TUNNEL_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ARRIVAL_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_NEXTHOP_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_NEXTHOP_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_NEXTHOP_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_NEXTHOP_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_NEXTHOP_TUNNEL_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_NEXTHOP_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_ORIGINAL_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ORIGINAL_PROFILE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_CURRENT_PROFILE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_CURRENT_PROFILE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_REAUTHORIZE_REASON)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_REAUTHORIZE_REASON].value);
         else if(pConditionKey == &FWPM_CONDITION_PEER_NAME)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_PEER_NAME].value);
         else if(pConditionKey == &FWPM_CONDITION_ORIGINAL_ICMP_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ORIGINAL_ICMP_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_QUARANTINE_EPOCH].value);

#if(NTDDI_VERSION >= NTDDI_WIN8)

         else if(pConditionKey == &FWPM_CONDITION_ALE_ORIGINAL_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_ORIGINAL_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_PACKAGE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_PACKAGE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)
#endif /// (NTDDI_VERSION >= NTDDI_WIN7)
#endif /// (NTDDI_VERSION >= NTDDI_VISTASP1)

         break;
      }
      case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
      case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD:
      case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
      case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_REMOTE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_REMOTE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_REMOTE_MACHINE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_REMOTE_MACHINE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_DESTINATION_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_DIRECTION)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_TUNNEL_TYPE].value);

#if(NTDDI_VERSION >= NTDDI_VISTASP1)

         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_FLAGS].value);

#if(NTDDI_VERSION >= NTDDI_WIN8)

         else if(pConditionKey == &FWPM_CONDITION_ALE_ORIGINAL_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_ORIGINAL_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_PACKAGE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_PACKAGE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)
#endif /// (NTDDI_VERSION >= NTDDI_VISTASP1)

         break;
      }

#if(NTDDI_VERSION >= NTDDI_WIN7)

      case FWPS_LAYER_NAME_RESOLUTION_CACHE_V4:
      case FWPS_LAYER_NAME_RESOLUTION_CACHE_V6:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_NAME_RESOLUTION_CACHE_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_NAME_RESOLUTION_CACHE_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_NAME_RESOLUTION_CACHE_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_PEER_NAME)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_NAME_RESOLUTION_CACHE_V4_PEER_NAME].value);

         break;
      }
      case FWPS_LAYER_ALE_RESOURCE_RELEASE_V4:
      case FWPS_LAYER_ALE_RESOURCE_RELEASE_V6:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_FLAGS].value);

#if(NTDDI_VERSION >= NTDDI_WIN8)

         else if(pConditionKey == &FWPM_CONDITION_ALE_PACKAGE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_ALE_PACKAGE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)

         break;
      }
      case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4:
      case FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_FLAGS].value);

#if(NTDDI_VERSION >= NTDDI_WIN8)

         else if(pConditionKey == &FWPM_CONDITION_ALE_PACKAGE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_ALE_PACKAGE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)

         break;
      }
      case FWPS_LAYER_ALE_CONNECT_REDIRECT_V4:
      case FWPS_LAYER_ALE_CONNECT_REDIRECT_V6:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_DESTINATION_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_FLAGS].value);

#if(NTDDI_VERSION >= NTDDI_WIN8)

         else if(pConditionKey == &FWPM_CONDITION_ALE_ORIGINAL_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_ORIGINAL_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_PACKAGE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_PACKAGE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)

         break;
      }
      case FWPS_LAYER_ALE_BIND_REDIRECT_V4:
      case FWPS_LAYER_ALE_BIND_REDIRECT_V6:
      {
         if(pConditionKey == &FWPM_CONDITION_ALE_APP_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_ALE_APP_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_ALE_USER_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_ALE_USER_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_FLAGS].value);

#if(NTDDI_VERSION >= NTDDI_WIN8)

         else if(pConditionKey == &FWPM_CONDITION_ALE_PACKAGE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_ALE_PACKAGE_ID].value);

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)

         break;
      }
      case FWPS_LAYER_STREAM_PACKET_V4:
      case FWPS_LAYER_STREAM_PACKET_V6:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_IP_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_IP_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_IP_LOCAL_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_REMOTE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_IP_REMOTE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_IP_LOCAL_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_SUB_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_SUB_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_DIRECTION)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_DIRECTION].value);
         else if(pConditionKey == &FWPM_CONDITION_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_FLAGS].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_TUNNEL_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_STREAM_PACKET_V4_TUNNEL_TYPE].value);

         break;
      }

#if(NTDDI_VERSION >= NTDDI_WIN8)

      case FWPS_LAYER_INBOUND_MAC_FRAME_ETHERNET:
      {
         if(pConditionKey == &FWPM_CONDITION_INTERFACE_MAC_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_INTERFACE_MAC_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_MAC_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_MAC_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_MAC_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_REMOTE_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_MAC_REMOTE_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ETHER_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_ETHER_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VLAN_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_VLAN_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_NDIS_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_NDIS_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_L2_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_ETHERNET_L2_FLAGS].value);

         break;
      }
      case FWPS_LAYER_OUTBOUND_MAC_FRAME_ETHERNET:
      {
         if(pConditionKey == &FWPM_CONDITION_INTERFACE_MAC_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_INTERFACE_MAC_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_LOCAL_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_MAC_LOCAL_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_REMOTE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_MAC_REMOTE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_LOCAL_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_MAC_LOCAL_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_REMOTE_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_MAC_REMOTE_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ETHER_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_ETHER_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VLAN_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_VLAN_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_NDIS_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_NDIS_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_L2_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_ETHERNET_L2_FLAGS].value);

         break;
      }
      case FWPS_LAYER_INBOUND_MAC_FRAME_NATIVE:
      {
         if(pConditionKey == &FWPM_CONDITION_NDIS_MEDIA_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_NDIS_MEDIA_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_NDIS_PHYSICAL_MEDIA_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_NDIS_PHYSICAL_MEDIA_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_NDIS_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_NDIS_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_L2_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_MAC_FRAME_NATIVE_L2_FLAGS].value);

         break;
      }
      case FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE:
      {
         if(pConditionKey == &FWPM_CONDITION_NDIS_MEDIA_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_NATIVE_NDIS_MEDIA_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_NDIS_PHYSICAL_MEDIA_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_NATIVE_NDIS_PHYSICAL_MEDIA_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_NATIVE_INTERFACE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_NATIVE_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_INTERFACE_INDEX)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_NATIVE_INTERFACE_INDEX].value);
         else if(pConditionKey == &FWPM_CONDITION_NDIS_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_NATIVE_NDIS_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_L2_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_MAC_FRAME_NATIVE_L2_FLAGS].value);

         break;
      }
      case FWPS_LAYER_INGRESS_VSWITCH_ETHERNET:
      {
         if(pConditionKey == &FWPM_CONDITION_MAC_SOURCE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_MAC_SOURCE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_SOURCE_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_MAC_SOURCE_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_DESTINATION_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_MAC_DESTINATION_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_DESTINATION_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_MAC_DESTINATION_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ETHER_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_ETHER_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VLAN_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_VLAN_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_VSWITCH_TENANT_NETWORK_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_VSWITCH_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_NETWORK_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_VSWITCH_NETWORK_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_VSWITCH_SOURCE_INTERFACE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_VSWITCH_SOURCE_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_VM_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_VSWITCH_SOURCE_VM_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_L2_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_ETHERNET_L2_FLAGS].value);

         break;
      }
      case FWPS_LAYER_EGRESS_VSWITCH_ETHERNET:
      {
         if(pConditionKey == &FWPM_CONDITION_MAC_SOURCE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_MAC_SOURCE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_SOURCE_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_MAC_SOURCE_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_DESTINATION_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_MAC_DESTINATION_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_MAC_DESTINATION_ADDRESS_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_MAC_DESTINATION_ADDRESS_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_ETHER_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_ETHER_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VLAN_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VLAN_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VSWITCH_TENANT_NETWORK_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VSWITCH_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_NETWORK_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VSWITCH_NETWORK_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VSWITCH_SOURCE_INTERFACE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VSWITCH_SOURCE_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_VM_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VSWITCH_SOURCE_VM_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VSWITCH_DESTINATION_INTERFACE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VSWITCH_DESTINATION_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_DESTINATION_VM_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_VSWITCH_DESTINATION_VM_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_L2_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_ETHERNET_L2_FLAGS].value);

         break;
      }
      case FWPS_LAYER_INGRESS_VSWITCH_TRANSPORT_V4:
      case FWPS_LAYER_INGRESS_VSWITCH_TRANSPORT_V6:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_SOURCE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_SOURCE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_DESTINATION_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_SOURCE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_SOURCE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_DESTINATION_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_VLAN_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_VLAN_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_TENANT_NETWORK_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_NETWORK_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_NETWORK_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_SOURCE_INTERFACE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_SOURCE_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_VM_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_SOURCE_VM_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_L2_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_L2_FLAGS].value);

         break;
      }
      case FWPS_LAYER_EGRESS_VSWITCH_TRANSPORT_V4:
      case FWPS_LAYER_EGRESS_VSWITCH_TRANSPORT_V6:
      {
         if(pConditionKey == &FWPM_CONDITION_IP_SOURCE_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_SOURCE_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_ADDRESS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_DESTINATION_ADDRESS].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_PROTOCOL)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_PROTOCOL].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_SOURCE_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_SOURCE_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_IP_DESTINATION_PORT)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_DESTINATION_PORT].value);
         else if(pConditionKey == &FWPM_CONDITION_VLAN_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VLAN_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_TENANT_NETWORK_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_TENANT_NETWORK_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_NETWORK_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_NETWORK_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_SOURCE_INTERFACE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_SOURCE_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_SOURCE_VM_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_SOURCE_VM_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_DESTINATION_INTERFACE_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_DESTINATION_INTERFACE_TYPE)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_DESTINATION_INTERFACE_TYPE].value);
         else if(pConditionKey == &FWPM_CONDITION_VSWITCH_DESTINATION_VM_ID)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_VSWITCH_DESTINATION_VM_ID].value);
         else if(pConditionKey == &FWPM_CONDITION_L2_FLAGS)
            pValue = &(pClassifyValues->incomingValue[FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_L2_FLAGS].value);

         break;
      }

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)
#endif /// (NTDDI_VERSION >= NTDDI_WIN7)

   }

   return pValue;
}

VOID
OvsIpSecClassifyFast(const FWPS_INCOMING_VALUES *inFixedValues,
                  const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
                  NET_BUFFER_LIST *layerNbl,
                  const VOID *classifyContext,
                  const FWPS_FILTER *filter,
                  UINT64 flowContext,
                  FWPS_CLASSIFY_OUT *classifyOut)
{
    FWP_VALUE *fwpProto = NULL;
    FWP_VALUE *fwpSrcIp = NULL;
    FWP_VALUE *fwpDstIp = NULL;
    FWP_VALUE *fwpFlags = NULL;
    FWP_VALUE *fwpIfIndex = NULL;
    FWP_VALUE *fwpSubIntIndex = NULL;
    FWP_VALUE *fwpNdisPort = NULL;

    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerNbl);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(classifyOut);

    fwpProto = OvsValueGetFromIncomingValues(inFixedValues, &FWPM_CONDITION_IP_PROTOCOL);
    fwpSrcIp = OvsValueGetFromIncomingValues(inFixedValues, &FWPM_CONDITION_IP_LOCAL_ADDRESS);
    fwpDstIp = OvsValueGetFromIncomingValues(inFixedValues, &FWPM_CONDITION_IP_REMOTE_ADDRESS);
    fwpFlags = OvsValueGetFromIncomingValues(inFixedValues, &FWPM_CONDITION_FLAGS);
    fwpIfIndex = OvsValueGetFromIncomingValues(inFixedValues, &FWPM_CONDITION_INTERFACE_INDEX);
    fwpSubIntIndex = OvsValueGetFromIncomingValues(inFixedValues, &FWPM_CONDITION_SUB_INTERFACE_INDEX);
    fwpNdisPort = OvsValueGetFromIncomingValues(inFixedValues, &FWPM_CONDITION_NDIS_PORT);

    if (fwpFlags != NULL && fwpFlags->uint32 == FWP_CONDITION_FLAG_IS_LOOPBACK) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (fwpDstIp != NULL && 10 != (&fwpDstIp->uint8)[3]) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    switch (inFixedValues->layerId)
    {
    case FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD:
    {
        FWPS_PACKET_LIST_INFORMATION0 packetInfo = { 0 };
        FwpsGetPacketListSecurityInformation0(
            layerNbl,
            FWPS_PACKET_LIST_INFORMATION_QUERY_IPSEC |
            FWPS_PACKET_LIST_INFORMATION_QUERY_INBOUND,
            &packetInfo
            );

        if (!packetInfo.ipsecInformation.inbound.isSecure) {
            return;
        }

        LOG("FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD %s", packetInfo.ipsecInformation.inbound.isSecure ? "SECURE" : "UNSECURE");

        FWPS_PACKET_INJECTION_STATE packetState = FwpsQueryPacketInjectionState(gNetworkInjectHandle, layerNbl, NULL);

        NdisRetreatNetBufferListDataStart(layerNbl,
            inMetaValues->ipHeaderSize + inMetaValues->transportHeaderSize,
            0,
            NULL,
            NULL);

        IPHdr *ipHdr = NdisGetDataBuffer(NET_BUFFER_LIST_FIRST_NB(layerNbl),
            sizeof *ipHdr, NULL,
            1 /*no align*/, 0);
        if (ipHdr != NULL) {
            if (packetState == FWPS_PACKET_INJECTED_BY_SELF || packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
                if (ipHdr->protocol == IPPROTO_GRE) {
                    LOG("INJECTED FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD GRE");
                }
                else if (ipHdr->protocol == IPPROTO_ESP) {
                    LOG("INJECTED FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD ESP");
                }
            }
            else {
                if (ipHdr->protocol == IPPROTO_GRE) {
                    LOG("FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD GRE");
                }
                else if (ipHdr->protocol == IPPROTO_ESP) {
                    LOG("FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD ESP");
                }
            }
        }

        NdisAdvanceNetBufferListDataStart(layerNbl,
            inMetaValues->ipHeaderSize + inMetaValues->transportHeaderSize,
            FALSE,
            NULL);

        classifyOut->actionType = FWP_ACTION_PERMIT;

        if (packetState == FWPS_PACKET_INJECTED_BY_SELF || packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
        }
        else {
            OVS_TUNNEL_PENDED_PACKET packet = { 0 };

            packet.classifyOut = classifyOut;
            packet.ipHeaderSize = inMetaValues->ipHeaderSize;
            packet.transportHeaderSize = inMetaValues->transportHeaderSize;
            packet.netBufferList = layerNbl;

            OvsTunnelAnalyzePacket(&packet);

            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            classifyOut->rights ^= FWPS_RIGHT_ACTION_WRITE;
        }
    }
    break;
    case FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE:
    {
        FWPS_PACKET_INJECTION_STATE packetState = FwpsQueryPacketInjectionState(gNetworkInjectHandle, layerNbl, NULL);
        if (packetState == FWPS_PACKET_INJECTED_BY_SELF || packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            LOG("IP INJECTED\n");
        }
        else {
            char *ipBuf[sizeof(IPHdr)];

            classifyOut->actionType = FWP_ACTION_PERMIT;

            NdisAdvanceNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(layerNbl), sizeof(EthHdr), FALSE, NULL);

            IPHdr *ipHdr = NdisGetDataBuffer(NET_BUFFER_LIST_FIRST_NB(layerNbl), sizeof(IPHdr), (PVOID)&ipBuf,
                1 /*no align*/, 0);
            if (ipHdr->protocol == IPPROTO_GRE) {
                NET_BUFFER_LIST *clonedNetBufferList = NULL;

                LOG("IP PROTOCOL GRE\n");

                classifyOut->actionType = FWP_ACTION_BLOCK;
                classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
                classifyOut->rights ^= FWPS_RIGHT_ACTION_WRITE;

                NTSTATUS status = FwpsAllocateNetBufferAndNetBufferList(gOvsSwitchContext->ovsPool.zeroSizePool,
                    0, 0, layerNbl->FirstNetBuffer->CurrentMdl,
                    layerNbl->FirstNetBuffer->DataOffset,
                    layerNbl->FirstNetBuffer->DataLength,
                    &clonedNetBufferList);
                if (NT_SUCCESS(status)) {
                    clonedNetBufferList->ParentNetBufferList = NULL;
                    status = FwpsInjectNetworkSendAsync(gNetworkInjectHandle, NULL, 0, UNSPECIFIED_COMPARTMENT_ID,
                        clonedNetBufferList, OvsIpSecInjectComplete2, NULL);
                    if (!NT_SUCCESS(status)) {
                        __debugbreak();
                        FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);
                    }
                }
            }
            NdisRetreatNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(layerNbl), sizeof(EthHdr), 0, NULL);
        }
    }
    break;
    case FWPS_LAYER_INBOUND_IPPACKET_V4:
    {
        FWPS_PACKET_INJECTION_STATE packetState = FwpsQueryPacketInjectionState(gNetworkInjectHandle, layerNbl, NULL);

        NdisRetreatNetBufferListDataStart(layerNbl,
            inMetaValues->ipHeaderSize,
            0,
            NULL,
            NULL);

        IPHdr *ipHdr = NdisGetDataBuffer(NET_BUFFER_LIST_FIRST_NB(layerNbl),
            sizeof *ipHdr, NULL,
            1 /*no align*/, 0);
        if (ipHdr != NULL) {
            if (packetState == FWPS_PACKET_INJECTED_BY_SELF || packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
                if (ipHdr->protocol == IPPROTO_GRE) {
                    LOG("INJECTED FWPS_LAYER_INBOUND_IPPACKET_V4 GRE");
                }
                else if (ipHdr->protocol == IPPROTO_ESP) {
                    LOG("INJECTED FWPS_LAYER_INBOUND_IPPACKET_V4 ESP");
                }
            }
            else {
                if (ipHdr->protocol == IPPROTO_GRE) {
                    LOG("FWPS_LAYER_INBOUND_IPPACKET_V4 GRE");
                }
                else if (ipHdr->protocol == IPPROTO_ESP) {
                    LOG("FWPS_LAYER_INBOUND_IPPACKET_V4 ESP");
                }
            }
        }

        if (packetState == FWPS_PACKET_INJECTED_BY_SELF || packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
        }
        else {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            classifyOut->rights ^= FWPS_RIGHT_ACTION_WRITE;

            NET_BUFFER_LIST* clonedNetBufferList = NULL;
            NTSTATUS status = FwpsAllocateCloneNetBufferList(layerNbl, NULL, NULL, 0, &clonedNetBufferList);
            if (NT_SUCCESS(status)) {
                status = FwpsInjectNetworkReceiveAsync(gNetworkInjectHandle, NULL, 0, inMetaValues->compartmentId,
                    fwpIfIndex->uint32, fwpSubIntIndex->uint32,
                    clonedNetBufferList, OvsIpSecInjectComplete2, NULL);
                if (!NT_SUCCESS(status)) {
                    FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);
                }
            }
        }

        NdisAdvanceNetBufferListDataStart(layerNbl,
            inMetaValues->ipHeaderSize,
            FALSE,
            NULL);
    }
    break;
    default:
        LOG("UNHANDLED");
        __debugbreak();
        break;
    }
}

/*
 * --------------------------------------------------------------------------
 * This is the classifyFn function of the datagram-data callout. It
 * allocates a packet structure to store the classify and meta data and
 * it references the net buffer list for out-of-band modification and
 * re-injection. The packet structure will be queued to the global packet
 * queue. The worker thread will then be signaled, if idle, to process
 * the queue.
 * --------------------------------------------------------------------------
 */
VOID
OvsTunnelClassify(const FWPS_INCOMING_VALUES *inFixedValues,
                  const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
                  VOID *layerData,
                  const VOID *classifyContext,
                  const FWPS_FILTER *filter,
                  UINT64 flowContext,
                  FWPS_CLASSIFY_OUT *classifyOut)
{
    OVS_TUNNEL_PENDED_PACKET packetStorage;
    OVS_TUNNEL_PENDED_PACKET *packet = &packetStorage;
    FWP_DIRECTION  direction;

    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    //__debugbreak();
    ASSERT(layerData != NULL);

    /* We don't have the necessary right to alter the packet flow */
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        /* XXX TBD revisit protect against other filters owning this packet */
        ASSERT(FALSE);
        goto Exit;
    }

    RtlZeroMemory(packet, sizeof(OVS_TUNNEL_PENDED_PACKET));

    /* classifyOut cannot be accessed from a different thread context */
    packet->classifyOut = classifyOut;

    if (inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V4) {
        direction =
            inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].\
            value.uint32;
    }
    else {
        ASSERT(inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6);
        direction =
            inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION].\
            value.uint32;
    }

    packet->netBufferList = layerData;

    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
        FWPS_METADATA_FIELD_COMPARTMENT_ID));

    ASSERT(direction == FWP_DIRECTION_INBOUND);

    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
        inMetaValues,
        FWPS_METADATA_FIELD_IP_HEADER_SIZE));
    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
        inMetaValues,
        FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE));

    packet->ipHeaderSize = inMetaValues->ipHeaderSize;
    packet->transportHeaderSize = inMetaValues->transportHeaderSize;

    ASSERT(inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8 == IPPROTO_UDP );
    OvsTunnelAnalyzePacket(packet);

Exit:
    ;
}


static NTSTATUS
OvsInjectPacketThroughActions(PNET_BUFFER_LIST pNbl,
                              OVS_TUNNEL_PENDED_PACKET *packet)
{
    NTSTATUS status;
    OvsIPv4TunnelKey tunnelKey;
    NET_BUFFER *pNb;
    ULONG sendCompleteFlags = 0;
    BOOLEAN dispatch;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;
    LOCK_STATE_EX lockState, dpLockState;
    LIST_ENTRY missedPackets;
    OvsCompletionList completionList;
    KIRQL irql;
    ULONG SendFlags = NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP;
    OVS_DATAPATH *datapath = &gOvsSwitchContext->datapath;

    ASSERT(gOvsSwitchContext);

    /* Fill the tunnel key */
    status = OvsSlowPathDecapVxlan(pNbl, &tunnelKey);

    if(!NT_SUCCESS(status)) {
        goto dropit;
    }

    pNb = NET_BUFFER_LIST_FIRST_NB(pNbl);

    NdisAdvanceNetBufferDataStart(pNb,
                                  packet->transportHeaderSize + packet->ipHeaderSize +
                                  sizeof(VXLANHdr),
                                  FALSE,
                                  NULL);

    /* Most likely (always) dispatch irql */
    irql = KeGetCurrentIrql();

    /* dispatch is used for datapath lock as well */
    dispatch = (irql == DISPATCH_LEVEL) ?  NDIS_RWL_AT_DISPATCH_LEVEL : 0;
    if (dispatch) {
        sendCompleteFlags |=  NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
    }

    InitializeListHead(&missedPackets);
    OvsInitCompletionList(&completionList, gOvsSwitchContext,
                          sendCompleteFlags);

    {
        POVS_VPORT_ENTRY vport = NULL;
        UINT32 portNo = 0;
        OVS_PACKET_HDR_INFO layers = { 0 };
        OvsFlowKey key = { 0 };
        UINT64 hash = 0;
        PNET_BUFFER curNb = NULL;
        OvsFlow *flow = NULL;

        fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNbl);

        /*
         * XXX WFP packets contain a single NBL structure.
         * Reassembeled packet "may" have multiple NBs, however, a simple test shows
         * that the packet still has a single NB (after reassemble)
         * We still need to check if the Ethernet header of the innet packet is in a single MD
         */

        curNb = NET_BUFFER_LIST_FIRST_NB(pNbl);
        ASSERT(curNb->Next == NULL);

        NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState, dispatch);

        /* Lock the flowtable for the duration of accessing the flow */
        OvsAcquireDatapathRead(datapath, &dpLockState, NDIS_RWL_AT_DISPATCH_LEVEL);

        SendFlags |= NDIS_SEND_FLAGS_DISPATCH_LEVEL;

        vport = OvsFindTunnelVportByDstPortAndType(gOvsSwitchContext,
                                                   htons(tunnelKey.dst_port),
                                                   OVS_VPORT_TYPE_VXLAN);

        if (vport == NULL){
            status = STATUS_UNSUCCESSFUL;
            goto unlockAndDrop;
        }

        ASSERT(vport->ovsType == OVS_VPORT_TYPE_VXLAN);

        portNo = vport->portNo;

        status = OvsExtractFlow(pNbl, portNo, &key, &layers, &tunnelKey);
        if (status != NDIS_STATUS_SUCCESS) {
            goto unlockAndDrop;
        }

        flow = OvsLookupFlow(datapath, &key, &hash, FALSE);
        if (flow) {
            OvsFlowUsed(flow, pNbl, &layers);
            datapath->hits++;

            OvsActionsExecute(gOvsSwitchContext, &completionList, pNbl,
                              portNo, SendFlags, &key, &hash, &layers,
                              flow->actions, flow->actionsLen);

            OvsReleaseDatapath(datapath, &dpLockState);
        } else {
            POVS_PACKET_QUEUE_ELEM elem;

            datapath->misses++;
            elem = OvsCreateQueueNlPacket(NULL, 0, OVS_PACKET_CMD_MISS,
                                          vport, &key, pNbl, curNb,
                                          TRUE, &layers);
            if (elem) {
                /* Complete the packet since it was copied to user buffer. */
                InsertTailList(&missedPackets, &elem->link);
                OvsQueuePackets(&missedPackets, 1);
            } else {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            goto unlockAndDrop;
        }

        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);

    }

    return status;

unlockAndDrop:
    OvsReleaseDatapath(datapath, &dpLockState);
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
dropit:
    pNbl = OvsCompleteNBL(gOvsSwitchContext, pNbl, TRUE);
    ASSERT(pNbl == NULL);
    return status;
}

static NTSTATUS
OvsInjectGrePacketThroughActions(PNET_BUFFER_LIST pNbl,
                                 OVS_TUNNEL_PENDED_PACKET *packet)
{
    NTSTATUS status;
    OvsIPv4TunnelKey tunnelKey;
    NET_BUFFER *pNb;
    ULONG sendCompleteFlags = 0;
    BOOLEAN dispatch;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;
    LOCK_STATE_EX lockState, dpLockState;
    LIST_ENTRY missedPackets;
    OvsCompletionList completionList;
    KIRQL irql;
    ULONG SendFlags = NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP;
    OVS_DATAPATH *datapath = &gOvsSwitchContext->datapath;
    UINT32 greOffset = 0;

    ASSERT(gOvsSwitchContext);

    /* Fill the tunnel key */
    status = OvsSlowPathDecapGre(pNbl, &tunnelKey);
    if(!NT_SUCCESS(status)) {
        goto dropit;
    }

    // fix GRE offset
    if (tunnelKey.flags & OVS_TNL_F_CSUM) {
        greOffset += 4;
    }
    if (tunnelKey.flags & OVS_TNL_F_KEY) {
        greOffset += 4;
    }

    pNb = NET_BUFFER_LIST_FIRST_NB(pNbl);

    NdisAdvanceNetBufferDataStart(pNb,
                                  packet->transportHeaderSize + packet->ipHeaderSize +
                                  sizeof(GREHdr) + greOffset,
                                  FALSE,
                                  NULL);

    /* Most likely (always) dispatch irql */
    irql = KeGetCurrentIrql();

    /* dispatch is used for datapath lock as well */
    dispatch = (irql == DISPATCH_LEVEL) ?  NDIS_RWL_AT_DISPATCH_LEVEL : 0;
    if (dispatch) {
        sendCompleteFlags |=  NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
    }

    InitializeListHead(&missedPackets);
    OvsInitCompletionList(&completionList, gOvsSwitchContext,
                          sendCompleteFlags);

    {
        POVS_VPORT_ENTRY vport = NULL;
        UINT32 portNo = 0;
        OVS_PACKET_HDR_INFO layers = { 0 };
        OvsFlowKey key = { 0 };
        UINT64 hash = 0;
        PNET_BUFFER curNb = NULL;
        OvsFlow *flow = NULL;

        fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNbl);

        /*
         * XXX WFP packets contain a single NBL structure.
         * Reassembeled packet "may" have multiple NBs, however, a simple test shows
         * that the packet still has a single NB (after reassemble)
         * We still need to check if the Ethernet header of the innet packet is in a single MD
         */

        curNb = NET_BUFFER_LIST_FIRST_NB(pNbl);
        ASSERT(curNb->Next == NULL);

        NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState, dispatch);

        /* Lock the flowtable for the duration of accessing the flow */
        OvsAcquireDatapathRead(datapath, &dpLockState, NDIS_RWL_AT_DISPATCH_LEVEL);

        SendFlags |= NDIS_SEND_FLAGS_DISPATCH_LEVEL;

        vport = OvsFindTunnelVportByDstPortAndType(gOvsSwitchContext,
                                            htons(tunnelKey.dst_port),
                                            OVS_VPORT_TYPE_GRE);

        if (vport == NULL){
            status = STATUS_UNSUCCESSFUL;
            goto unlockAndDrop;
        }

        ASSERT(vport->ovsType == OVS_VPORT_TYPE_GRE);

        portNo = vport->portNo;

        status = OvsExtractFlow(pNbl, portNo, &key, &layers, &tunnelKey);
        if (status != NDIS_STATUS_SUCCESS) {
            goto unlockAndDrop;
        }

        flow = OvsLookupFlow(datapath, &key, &hash, FALSE);
        if (flow) {
            OvsFlowUsed(flow, pNbl, &layers);
            datapath->hits++;

            OvsActionsExecute(gOvsSwitchContext, &completionList, pNbl,
                              portNo, SendFlags, &key, &hash, &layers,
                              flow->actions, flow->actionsLen);

            OvsReleaseDatapath(datapath, &dpLockState);
        } else {
            POVS_PACKET_QUEUE_ELEM elem;

            datapath->misses++;
            elem = OvsCreateQueueNlPacket(NULL, 0, OVS_PACKET_CMD_MISS,
                                          vport, &key, pNbl, curNb,
                                          TRUE, &layers);
            if (elem) {
                /* Complete the packet since it was copied to user buffer. */
                InsertTailList(&missedPackets, &elem->link);
                OvsQueuePackets(&missedPackets, 1);
            } else {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            goto unlockAndDrop;
        }

        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);

    }

    return status;

unlockAndDrop:
    OvsReleaseDatapath(datapath, &dpLockState);
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
dropit:
    pNbl = OvsCompleteNBL(gOvsSwitchContext, pNbl, TRUE);
    ASSERT(pNbl == NULL);
    return status;
}

#pragma warning(pop)
