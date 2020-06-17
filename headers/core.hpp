#ifndef CORE_H
#define CORE_H

#include <stdlib.h>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <HttpLayer.h>
#include <EthLayer.h>
#include <IcmpLayer.h>

using namespace std;
using namespace pcpp;
class Core
{
    private:
    public:
        Core(){};
        string getProtocolTypeAsString(ProtocolType protocolType)
        {
            switch (protocolType)
            {
            case Ethernet:
                return "Ethernet";
            case IPv4:
                return "IPv4";
            case TCP:
                return "TCP";
            case ICMP:
                return "ICMP";
            case HTTPRequest:
            case HTTPResponse:
                return "HTTP";
            case UDP:
                return "UDP";
            default:
                return "Unknown";
            }
        }

        string printTcpFlags(TcpLayer *tcpLayer)
        {
            string result = "";
            if (tcpLayer->getTcpHeader()->synFlag == 1)
                result += "SYN ";
            if (tcpLayer->getTcpHeader()->ackFlag == 1)
                result += "ACK ";
            if (tcpLayer->getTcpHeader()->pshFlag == 1)
                result += "PSH ";
            if (tcpLayer->getTcpHeader()->cwrFlag == 1)
                result += "CWR ";
            if (tcpLayer->getTcpHeader()->urgFlag == 1)
                result += "URG ";
            if (tcpLayer->getTcpHeader()->eceFlag == 1)
                result += "ECE ";
            if (tcpLayer->getTcpHeader()->rstFlag == 1)
                result += "RST ";
            if (tcpLayer->getTcpHeader()->finFlag == 1)
                result += "FIN ";

            return result;
        }

        string printToTcpOptionType(TcpOptionType optionType)
        {
            switch (optionType)
            {
            case PCPP_TCPOPT_NOP:
                return "NOP";
            case PCPP_TCPOPT_TIMESTAMP:
                return "Timestamp";
            default:
                return "Other";
            }
        }

        string printToIcmpType(IcmpLayer *icmpLayer)
        {
            IcmpMessageType message = icmpLayer->getMessageType();
            int code = icmpLayer->getIcmpHeader()->code;
            string result = "\nICMP Header : \n";
            switch (message)
            {
            case ICMP_ECHO_REPLY:
                return "Type : 0 (Echo Reply)\nCode : 0";
            case ICMP_DEST_UNREACHABLE:
            {

                result += "Type : 3 (Destination Unreachable)\n";
                IcmpDestUnreachableCodes codes = (IcmpDestUnreachableCodes)(icmpLayer->getIcmpHeader()->code);
                switch (codes)
                {
                case IcmpNetworkUnreachable:
                    return result += "Code : 0 (Destination network unreachable)\n";
                case IcmpHostUnreachable:
                    return result += "Code : 1 (Destination host unreachable)\n";
                case IcmpProtocolUnreachable:
                    return result += "Code : 2 (Destination protocol unreachable)\n";
                case IcmpPortUnreachable:
                    return result += "Code : 3 (Destination port unreachable)\n";
                case IcmpDatagramTooBig:
                    return result += "Code : 4 (Fragmentation required, and DF flag set)\n";
                case IcmpSourceRouteFailed:
                    return result += "Code : 5 (Source route failed)\n";
                case IcmpDestinationNetworkUnknown:
                    return result += "Code : 6 (Destination network unknown)\n";
                case IcmpDestinationHostUnknown:
                    return result += "Code : 7 (Destination host unknown)\n";
                case IcmpSourceHostIsolated:
                    return result += "Code : 8 (Source host isolated)\n";
                case IcmpDestinationNetworkProhibited:
                    return result += "Code : 9 (Network administratively prohibited)\n";
                case IcmpDestinationHostProhibited:
                    return result += "Code : 10 (Host administratively prohibited)\n";
                case IcmpNetworkUnreachableForTypeOfService:
                    return result += "Code : 11 (Network unreachable for ToS)\n";
                case IcmpHostUnreachableForTypeOfService:
                    return result += "Code : 12 (Host unreachable for ToS)\n";
                case IcmpCommunicationProhibited:
                    return result += "Code : 13 (Communication administratively prohibited)\n";
                case IcmpHostPrecedenceViolation:
                    return result += "Code : 14 (Host Precedence Violation)\n";
                case IcmpPrecedenceCutoff:
                    return result += "Code : 15 (Precedence cutoff in effect)\n";
                }
            }
            case ICMP_SOURCE_QUENCH:
                return result += "Type : 4 (Source Quench)\nCode : 0\n";
            case ICMP_REDIRECT:
                result += "Type : 5 (Redirect Message)\n";

                if (code == 0)
                {
                    return result += "Code : 0 (Redirect Datagram for the Network)\n";
                }
                else if (code == 1)
                {
                    return result += "Code : 1 (Redirect Datagram for the Host)\n";
                }
                else if (code == 2)
                {
                    return result += "Code : 2 (Redirect Datagram for the ToS & network)\n";
                }
                else if (code == 3)
                {
                    return result += "Code : 3 (Redirect Datagram for the ToS & host)\n";
                }

            case ICMP_ECHO_REQUEST:
                return result += "Type : 8 (Echo Request)\nCode : 0\n";
            case ICMP_ROUTER_ADV:
                return result += "Type : 9 (Router Advertisement)\nCode : 0\n";
            case ICMP_ROUTER_SOL:
                return result += "Type : 10 (Router Solicitation)\nCode : 0\n";
            case ICMP_TIME_EXCEEDED:
                result += "Type : 11 (Time Exceeded)\n";
                if (code == 0)
                {
                    return result += "Code : 0 (TTL expired in transit)\n";
                }
                else if (code == 1)
                {
                    return result = +"Code : 1 (Fragment reassembly time exceeded)\n";
                }
            case ICMP_PARAM_PROBLEM:
                result += "Type : 12 (Parameter Problem: Bad IP header)\n";
                if (code == 0)
                    return result += "Code : 0 (Pointer indicates the error)\n";
                else if (code == 1)
                    return result += "Code : 1 (Missing a required option)\n";
                else if (code == 2)
                    return result += "Code : 2 (Bad length)\n";
            case ICMP_TIMESTAMP_REQUEST:
                return result += "Type : 13 (Timestamp)\nCode : 0\n";
            case ICMP_TIMESTAMP_REPLY:
                return result += "Type : 14 (Timestamp Reply)\nCode :0\n";
            case ICMP_INFO_REQUEST:
                return result += "Type : 15 (Information Request)\nCode : 0 \n";
            case ICMP_INFO_REPLY:
                return result += "Type : 16 (Information Reply)\nCode : 0\n";
            case ICMP_ADDRESS_MASK_REQUEST:
                return result += "Type : 17 (Address Mask Request)\nCode :0\n";
            case ICMP_ADDRESS_MASK_REPLY:
                return result += "Type : 18 (ICMP_ADDRESS_MASK_REPLY)\nCode : 0\n";
            case ICMP_UNSUPPORTED:
                return result += "Type : 255\nCode : 0\n";
            default:
                return result += "Type : \nCode : \n";
            }
            return result;
        }

        string printHttpMethod(HttpRequestLayer::HttpMethod httpMethod)
        {
            switch (httpMethod)
            {
            case HttpRequestLayer::HttpGET:
                return "GET";
            case HttpRequestLayer::HttpPOST:
                return "POST";
            default:
                return "Other";
            }
        }
};
#endif