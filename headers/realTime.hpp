#ifndef REALTIME_H
#define REALTIME_H

#include <string.h>
#include <stdlib.h>
#include <Packet.h>
#include <PcapLiveDeviceList.h>
#include <PlatformSpecificUtils.h>
#include <PcapFileDevice.h>


using namespace std;
using namespace pcpp;
class RealTime{
    private:
        PcapFileWriterDevice *pcapWriter;

    public:
       
        RealTime()
        {
            this->pcapWriter = new PcapFileWriterDevice("output.pcap",LINKTYPE_ETHERNET);
        };

        bool openFile(){
            if(!this->pcapWriter->open()){
                return false;
            }
            return true;
        }

        bool writePacketsToFile(RawPacketVector *rawPackets){
            if(!this->pcapWriter->writePackets(*rawPackets))
                return false;
            return true;
        }

        void closeFile(){
            this->pcapWriter->close();
        }

        string getStats(pcap_stat stats){
            this->pcapWriter->getStatistics(stats);
            string result = "Written " + to_string(stats.ps_recv)  + " packets successfully to pcap writer and " + to_string(stats.ps_drop) + " packets couldn't not be written";
            return result;
        }
        
};
#endif