#ifndef READ_H
#define READ_H

#include <string.h>
#include <stdlib.h>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapLiveDeviceList.h>
#include <PlatformSpecificUtils.h>
#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <HttpLayer.h>
#include <EthLayer.h>
#include <IcmpLayer.h>
#include <UdpLayer.h>
#include "core.hpp"

using namespace pcpp;
using namespace std;
class Read{
    private:
        string fileName;
        IFileReaderDevice *reader;
    public:
        Read(string fileName){
            this->fileName = fileName;
            this->reader = IFileReaderDevice::getReader(this->fileName.c_str());
        }

        bool checkInput(){
            if(this->fileName.empty())
                return false;
            return true;
        }

        bool openReader(){
            if(reader == NULL)
                return false;
            if(!reader->open())
                return false;
            return true;
        }

        void readPcapFile(){
            int count = 0;
            RawPacket rawPacket;
            Core core;
            reader->setFilter("tcp or udp or icmp");
            while (reader->getNextPacket(rawPacket))
            {
                count++;
                printf("\n# %d\n",count);
                Packet parsedPacket(&rawPacket);
                for(Layer *currLayer =parsedPacket.getFirstLayer(); currLayer != NULL; currLayer = currLayer->getNextLayer()){
                    printf("Layer type : %s; Total data : %d [bytes]; Layer data : %d [bytes]; Layer payload : %d [bytes]\n",
                       core.getProtocolTypeAsString(currLayer->getProtocol()).c_str(), // get layer type
                       (int)currLayer->getDataLen(),                                   // get total lengt of layer
                       (int)currLayer->getHeaderLen(),                                 // get the header lengt of layer
                       (int)currLayer->getLayerPayloadSize()                           // get the payload lenght of the layer
                    );
                }
                EthLayer *ethernetLayer = parsedPacket.getLayerOfType<EthLayer>();
                if (ethernetLayer != NULL)
                {
                    printf("\n ## Ethernet Header ##");
                    printf("\nSource MAC address : %s\n", ethernetLayer->getSourceMac().toString().c_str());
                    printf("Destination MAC address : %s\n", ethernetLayer->getDestMac().toString().c_str());
                    printf("Ether type = 0x%X\n", ntohs(ethernetLayer->getEthHeader()->etherType));
                }

                
                IcmpLayer *icmpLayer = parsedPacket.getLayerOfType<IcmpLayer>();
                if (icmpLayer != NULL)
                {   
                    printf("\n ## ICMP Header ##");
                    printf(core.printToIcmpType(icmpLayer).c_str());
                    printf("Checksum : 0x%X\n", (int)ntohs(icmpLayer->getIcmpHeader()->checksum));
                    
                }

                
                IPv4Layer *ipv4Layer = parsedPacket.getLayerOfType<IPv4Layer>();
                if (ipv4Layer != NULL)
                {
                    printf("\n ## IP Header ## ");
                    printf("\nSource IP address : %s\n", ipv4Layer->getSrcIpAddress().toString().c_str());
                    printf("Destination IP address : %s\n", ipv4Layer->getDstIpAddress().toString().c_str());
                    printf("IP ID : 0x%X\n", ntohs(ipv4Layer->getIPv4Header()->ipId));
                    printf("TTL : %d\n", ipv4Layer->getIPv4Header()->timeToLive);
                }
               
                TcpLayer *tcpLayer = parsedPacket.getLayerOfType<TcpLayer>();
                if (tcpLayer != NULL)
                {
                    printf("\n ## TCP Header ##");
                    printf("\nSource TCP port : %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portSrc));
                    printf("Destination TCP port : %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portDst));
                    printf("Sequence Number : %d\n",(int)ntohs(tcpLayer->getTcpHeader()->sequenceNumber));
                    printf("Acknowledgement Number : %d\n",(int)ntohs(tcpLayer->getTcpHeader()->ackNumber));
                    printf("Data Offset : %d\n",(int)ntohs(tcpLayer->getTcpHeader()->dataOffset));
                    printf("TCP flags : %s\n", core.printTcpFlags(tcpLayer).c_str());
                    printf("Window size : %d\n", (int)ntohs(tcpLayer->getTcpHeader()->windowSize));
                    printf("Checksum : 0x%X\n",(int)ntohs(tcpLayer->getTcpHeader()->headerChecksum));
                    printf("Urgent Pointer : %d\n",(int)ntohs(tcpLayer->getTcpHeader()->urgentPointer));

                    printf("TCP options : ");
                    for (TcpOption tcpOption = tcpLayer->getFirstTcpOption(); tcpOption.isNotNull(); tcpOption = tcpLayer->getNextTcpOption(tcpOption))
                    {
                        printf("%s ", core.printToTcpOptionType(tcpOption.getTcpOptionType()).c_str());
                    }
                    printf("\n");
                }
               
                UdpLayer *udpLayer = parsedPacket.getLayerOfType<UdpLayer>();
                if(udpLayer != NULL)
                {
                    printf("\n ## UDP Header ## : ");
                    printf("\nSource port : %d\n",(int)ntohs(udpLayer->getUdpHeader()->portSrc));
                    printf("Destination port : %d\n",(int)ntohs(udpLayer->getUdpHeader()->portDst));
                    printf("UDP lengt : %d\n",(int)ntohs(udpLayer->getUdpHeader()->length));
                    printf("Check sum : 0x%X\n",(int)ntohs(udpLayer->getUdpHeader()->headerChecksum));
                }   
            }
            reader->close();
            
        }

        string getStats(){
            pcap_stat stats;
            this->reader->getStatistics(stats);
            string result = "Read " + to_string(stats.ps_recv) + " packets successfully and " + to_string(stats.ps_drop) + " packets couldn't be read\n";
            return result;
        }

};

#endif