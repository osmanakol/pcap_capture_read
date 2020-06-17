#ifndef DEVICE_H
#define DEVICE_H

#include <stdlib.h>
#include <Packet.h>
#include <PcapLiveDeviceList.h>
#include <PlatformSpecificUtils.h>
#include <PcapFileDevice.h>

using namespace std;
using namespace pcpp;

class Device{
    private:
        string interfaceNameOrIp;
        PcapLiveDevice *dev;
    public:
        Device(string nameOrIp){
            this->interfaceNameOrIp = nameOrIp;
            this->dev = NULL;
        }

        bool checkInput(){
            if(this->interfaceNameOrIp.empty())
                return false;   
            IPv4Address ipv4(this->interfaceNameOrIp);
            if(ipv4.isValid()){
                this->dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ipv4);
                if(dev == NULL)
                    return false;
            }
            else{
                this->dev = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(this->interfaceNameOrIp);
                if(dev == NULL)
                    return false;
            }
            return true;
        }

        static void printDeviceList(){
            int counter = 0;
            vector<PcapLiveDevice *> devList = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
            for(vector<PcapLiveDevice *>::iterator iter = devList.begin(); iter != devList.end(); iter++){
                counter++;
                printf("%d - Name : %s IP Address : %s\n",counter,(*iter)->getName(),(*iter)->getIPv4Address().toString().c_str());
            }
        }

        void deviceInfo(){
            printf("\n## Interface informations ##\n");
            printf("Interface name : %s\n", this->dev->getName());
            printf("Interface Description : %s\n", this->dev->getDesc());
            printf("MAC address : %s\n", this->dev->getMacAddress().toString().c_str());
            printf("Default gateway : %s\n", this->dev->getDefaultGateway().toString().c_str());
            if (this->dev->getDnsServers().size() > 0)
            {
                printf("DNS Server : %s\n", this->dev->getDnsServers().at(0).toString().c_str());
            } 
        }

        RawPacketVector capturePackets(){
            RawPacketVector packetVector;
            printf("\nStarting capture with packet vector\n");
            if(!this->dev->open()){
                return packetVector;
            }

            if(this->dev->verifyFilter("tcp or udp or icmp")){
                this->dev->setFilter("tcp or udp or icmp");
            }

            if(!this->dev->startCapture(packetVector)){
                return packetVector;
            }
            
            PCAP_SLEEP(10);
            this->dev->stopCapture();
            this->dev->close();
            return packetVector;
        }
};
#endif