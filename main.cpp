#if !defined(WIN32) && !defined(WINx64)
#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#endif
#include <iostream>
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
#include "headers/core.hpp"
#include "headers/realTime.hpp"
#include "headers/device.hpp"
#include "headers/read.hpp"


using namespace std;
using namespace pcpp;

int main(int argc, char *argv[])
{
    string file = "";
    Core core;

    //string file = "C:\\Users\\osman\\Desktop\\nettsi\\pcap_reader\\test.pcap";
    int choose = 0;
    string answer;
    cout <<"Welcome pcap capture and reader program" << endl;
    while(choose != 3){   
        cout <<"\n1 - Realtime network capturing" << endl;
        cout <<"2 - Existing pcap file"<< endl;
        cout <<"3 - Exit"<<endl;
        cout <<"Please enter the number what you want to choose : ";
        cin>>answer;
        cout << "\n";
        choose = stoi(answer);
        if(choose == 0){
            cout << "Please enter valid like 1, 2 or 3\n"<< endl;
            cin>>answer;
            choose = stoi(answer);
        }
        else if(choose == 1){
            try
            {
                RealTime realTime;
                Device *device;
                string interfaceNameOrIp = "";
                device->printDeviceList();
                cout << "Please enter the name or ip what you want to listen to network : ";
                cin >> interfaceNameOrIp;
                device = new Device(interfaceNameOrIp);
                if(!device->checkInput()){
                    printf("Please enter the valid device name or ip!!!\n");
                    continue;
                }
                device->deviceInfo();
                RawPacketVector packetVector=device->capturePackets();
                if(packetVector.size() == 0){
                    cout << "Something went wrong, please try again" <<endl;
                    continue;
                }
                if(!realTime.openFile()){
                    printf("Something went wrong");
                }
                if(!realTime.writePacketsToFile(&packetVector)){
                    printf("something went wrong!!");
                }
                pcap_stat stats;
                string value = realTime.getStats(stats);
                printf("%s",value.c_str());
                realTime.closeFile();
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }
            catch(...){
                cout << "Unknown Error";
            }
        }
        else if(choose == 2){
            try
            {
                cout<< "Enter your pcap file full path (C:\\users\\user_name\\desktop\\my_pcap.pcap) : ";
                cin >> file;
                if (file.empty())
                {
                    cout << "Please check your pcap file path!!"<<endl;
                    continue;
                }
                Read read(file);
                if(!read.checkInput()){
                    cout<< "Please check your pcap file path!!!"<<endl;
                    continue;
                } 
                if(!read.openReader()){
                    cout << "Pcap file can not open, please try again!!"<<endl;
                    continue;
                }
                read.readPcapFile();
                string value = read.getStats();
                printf("%s\n",value.c_str());
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }
            catch(...){
                cout << "Unknown Error";
            }
        }
        else if(choose == 3 ){
            cout <<"See you soon :)"<<endl;
            exit(1);
        }
        else{
            cout << "Please enter valid number like 1, 2 or 3 "<<endl;;
        }
    } 
    return 0;
}
