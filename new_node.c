//
//  Intel Edison Playground
//  Copyright (c) 2015 Damian Kołakowski. All rights reserved.
//

#include <wchar.h>
#include <iostream>
#include <stdlib.h>
#include <errno.h>
#include <curses.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <stack>
#include <vector>
#include <sstream>
#include "sha256.h"
#include "hmac-sha1.h"
#include <openssl/hmac.h>
#include <cmath>
#include <iomanip>
#include <pthread.h>
#include <sys/syscall.h>
#include <cstring>

using namespace std;

clock_t t1,t2,t3,t4;
pthread_mutex_t lock;
uint8_t* msg_get;
int msg_length;
bool receive_first_packet;
int packet_count;

uint8_t mac_reader[6] = {0xB8,0x27,0xEB,0xAB,0xBA,0x26};
uint8_t LN1[4] = { 0x43,0x59,0x43,0x55 };
uint8_t kn1[] = "ABCD";
string msg_to_reader;

string hmacHex(string key, string msg)
{
    unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    HMAC_Init_ex(&hmac, &key[0], key.length(), EVP_sha256(), NULL);
    HMAC_Update(&hmac, (unsigned char*)&msg[0], msg.length());
    unsigned int len = 32;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    std::stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < len; i++)
    {   
        ss << hex << setw(2)  << (unsigned int)hash[i];
    }

    return (ss.str());
}

struct hci_request ble_hci_request(uint16_t ocf, int clen, void * status, void * cparam)
{
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = ocf;
	rq.cparam = cparam;
	rq.clen = clen;
	rq.rparam = status;
	rq.rlen = 1;
	return rq;
}

le_set_advertising_data_cp ble_hci_params_for_set_adv_data(char * name)
{
	int name_len = strlen(name);

	le_set_advertising_data_cp adv_data_cp;
	memset(&adv_data_cp, 0, sizeof(adv_data_cp));

	// Build simple advertisement data bundle according to:
	// - ​"Core Specification Supplement (CSS) v5" 
	// ( https://www.bluetooth.org/en-us/specification/adopted-specifications )

	adv_data_cp.data[0] = 0x02; // Length.
	adv_data_cp.data[1] = 0x01; // Flags field.
	adv_data_cp.data[2] = 0x01; // LE Limited Discoverable Flag set

	adv_data_cp.data[3] = name_len + 1; // Length.
	adv_data_cp.data[4] = 0x09; // Name field.
	memcpy(adv_data_cp.data + 5, name, name_len);

	adv_data_cp.length = 5 + strlen(name);

	return adv_data_cp;
}

struct scan_param {
	int ret, status;
	int device;
	le_set_scan_parameters_cp scan_params_cp;
	struct hci_request scan_params_rq;
	le_set_event_mask_cp event_mask_cp;
	struct hci_request set_mask_rq;
	struct hci_request disable_adv_rq;
	le_set_scan_enable_cp scan_cp;
	struct hci_request enable_adv_rq;
	struct hci_filter nf;
	uint8_t buf[HCI_MAX_EVENT_SIZE];
	bool *count_bit;
};

struct advertise_param {
	int ret, status;
	int device;
	le_set_advertising_parameters_cp adv_params_cp;
	struct hci_request adv_params_rq;
	le_set_advertising_data_cp adv_data_cp;
	struct hci_request adv_data_rq;
	le_set_advertise_enable_cp advertise_cp;
	struct hci_request enable_adv_rq;

};

void * scan(void*);
int init_scan(struct scan_param*);
int close_scan(struct scan_param*);
int init_advertise(struct advertise_param*);
void * advertise(void*);
void close_advertise(struct advertise_param*);
bool if_mac_check( uint8_t* );
int set_packet_count(int);
void set_msg_get(int, uint8_t*);
void print_msg_get();
bool if_count_bit_full ( bool*, int );
void encrypt();

int main()
{
	struct scan_param my_scan_param;
	struct advertise_param my_advertise_param;
	pthread_t my_thread[6];
	pthread_t my_thread_advertise;
	pthread_mutex_init(&lock,NULL);
	init_scan(&my_scan_param);
	msg_length = 0;
	receive_first_packet = false;
	packet_count = 0;
	
	printf("Scanning....\n");
	
	t1 = clock();
	int i = 0;
	for (i = 0; i < 6; ++i) {
		printf("\ncreate thread %d\n", i);
		pthread_create(&my_thread[i], NULL, scan,(void*)&my_scan_param);
	}
	
	for (i = 0; i < 6; ++i) {
		pthread_join(my_thread[i],NULL);
	}
	
	t2 = clock();
	printf("\n-----------------------\n");
	printf("\nscan total time = %lf\n", (double)(t2 - t1)/CLOCKS_PER_SEC);
	printf("\n-----------------------\n");
	// Disable scanning.
	printf("\nprint msg........\n");
	
	print_msg_get();
	close_scan(&my_scan_param);
	
	encrypt();
	
	init_advertise(&my_advertise_param);
	pthread_create(&my_thread_advertise, NULL, advertise,(void*)&my_advertise_param);
	pthread_join(my_thread_advertise,NULL);
	close_advertise(&my_advertise_param);
	
	return 0;
}

int init_scan( struct scan_param* my_scan_param ) {

	// Get HCI device.
	my_scan_param->device = hci_open_dev(hci_get_route(NULL));
	if ( my_scan_param->device < 0 ) { 
		perror("Failed to open HCI device.");
		return 0; 
	}

	// Set BLE scan parameters.
	
	memset(&my_scan_param->scan_params_cp, 0, sizeof(my_scan_param->scan_params_cp));
	my_scan_param->scan_params_cp.type 			= 0x00; 
	my_scan_param->scan_params_cp.interval 		= htobs(0x0010);
	my_scan_param->scan_params_cp.window 			= htobs(0x0010);
	my_scan_param->scan_params_cp.own_bdaddr_type 	= 0x00; // Public Device Address (default).
	my_scan_param->scan_params_cp.filter 			= 0x00; // Accept all.

	my_scan_param->scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, &my_scan_param->status, &my_scan_param->scan_params_cp);
	
	my_scan_param->ret = hci_send_req(my_scan_param->device, &my_scan_param->scan_params_rq, 1000);
	if ( my_scan_param->ret < 0 ) {
		hci_close_dev(my_scan_param->device);
		perror("Failed to set scan parameters data.");
		return 0;
	}

	// Set BLE events report mask.


	memset(&my_scan_param->event_mask_cp, 0, sizeof(le_set_event_mask_cp));
	int i = 0;
	for ( i = 0 ; i < 8 ; i++ ) my_scan_param->event_mask_cp.mask[i] = 0xFF;

	my_scan_param->set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &my_scan_param->status, &my_scan_param->event_mask_cp);
	my_scan_param->ret = hci_send_req(my_scan_param->device, &my_scan_param->set_mask_rq, 1000);
	if ( my_scan_param->ret < 0 ) {
		hci_close_dev(my_scan_param->device);
		perror("Failed to set event mask.");
		return 0;
	}

	// Enable scanning.

	memset(&my_scan_param->scan_cp, 0, sizeof(my_scan_param->scan_cp));
	my_scan_param->scan_cp.enable 		= 0x01;	// Enable flag.
	my_scan_param->scan_cp.filter_dup 	= 0x00; // Filtering disabled.

	my_scan_param->enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &my_scan_param->status, &my_scan_param->scan_cp);

	my_scan_param->ret = hci_send_req(my_scan_param->device, &my_scan_param->enable_adv_rq, 1000);
	if ( my_scan_param->ret < 0 ) {
		hci_close_dev(my_scan_param->device);
		perror("Failed to enable scan.");
		return 0;
	}

	// Get Results.

	my_scan_param->nf;
	hci_filter_clear(&my_scan_param->nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &my_scan_param->nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &my_scan_param->nf);
	if ( setsockopt(my_scan_param->device, SOL_HCI, HCI_FILTER, &my_scan_param->nf, sizeof(my_scan_param->nf)) < 0 ) {
		hci_close_dev(my_scan_param->device);
		perror("Could not set socket options\n");
		return 0;
	}

}

int close_scan(struct scan_param* my_scan_param) {
	
	memset(&my_scan_param->scan_cp, 0, sizeof(my_scan_param->scan_cp));
	my_scan_param->scan_cp.enable = 0x00;	// Disable flag.

	my_scan_param->disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &my_scan_param->status, &my_scan_param->scan_cp);
	my_scan_param->ret = hci_send_req(my_scan_param->device, &my_scan_param->disable_adv_rq, 1000);
	if ( my_scan_param->ret < 0 ) {
		hci_close_dev(my_scan_param->device);
		perror("Failed to disable scan.");
		return 0;
	}

	hci_close_dev(my_scan_param->device);
}
void* scan(void* my_scan_param1) {
	struct scan_param* my_scan_param = (struct scan_param*) my_scan_param1;
	int len;
	
	pthread_mutex_lock(&lock);
	printf("\nthread tid = %lu, pid = %ld\n",pthread_self(),syscall(SYS_gettid));
	
	memset(my_scan_param->buf,0,HCI_MAX_EVENT_SIZE);
	len = read(my_scan_param->device, my_scan_param->buf, sizeof(my_scan_param->buf));
	while ( if_mac_check(my_scan_param->buf) == false ) {
		memset(my_scan_param->buf,0,HCI_MAX_EVENT_SIZE);
		len = read(my_scan_param->device, my_scan_param->buf, sizeof(my_scan_param->buf));	
	}
	while ( 1 ) {
		if (receive_first_packet == true) {
			if ( if_count_bit_full(my_scan_param->count_bit,packet_count) == true ) {
				pthread_mutex_unlock(&lock);
				pthread_exit(0);
				break;
			}
		}
		
		if (my_scan_param->buf[25] == 0x30 && receive_first_packet == false) {
			printf("\nget first packet.....\n");
			printf("\nIts length is %d\n",(int)my_scan_param->buf[26]);
			msg_length = (int)my_scan_param->buf[26];
			msg_get = new uint8_t[msg_length];
			memset(msg_get,0,msg_length);
			if (set_packet_count(msg_length) <= 0) {
				printf("\nset packet_count error\n");
				// pthread_exit(EXIT_FAILURE);
			}
			my_scan_param->count_bit = new bool[packet_count];
			memset(my_scan_param->count_bit, 0, 6);
			set_msg_get(true, my_scan_param->buf);
			my_scan_param->count_bit[0] = true;
			receive_first_packet = true;
			break;
		}
		else if ( receive_first_packet == true ){
			if ( my_scan_param->count_bit[(int)my_scan_param->buf[25] -48] == false ) {
				printf("\n%dth packet.....\n",(int)my_scan_param->buf[25] -48);
				set_msg_get(false, my_scan_param->buf);
				my_scan_param->count_bit[(int)my_scan_param->buf[25] -48] = true;
				break;
			}
		}
		
		memset(my_scan_param->buf,0,HCI_MAX_EVENT_SIZE);
		len = read(my_scan_param->device, my_scan_param->buf, sizeof(my_scan_param->buf));
	}
	int j = 0;
	for (j = 0; j < 45; ++j ){
		printf("%02x ",my_scan_param->buf[j]);
	}
	printf("\n\n");
	pthread_mutex_unlock(&lock);
	pthread_exit(0);
}

int init_advertise(struct advertise_param* my_advertise_param) {


	// Get HCI device.

	my_advertise_param->device = hci_open_dev(hci_get_route(NULL));
	if ( my_advertise_param->device < 0 ) { 
		perror("Failed to open HC device.");
		return 0; 
	}

	// Set BLE advertisement parameters.
	
	memset(&my_advertise_param->adv_params_cp, 0, sizeof(my_advertise_param->adv_params_cp));
	my_advertise_param->adv_params_cp.min_interval = htobs(0x0800);
	my_advertise_param->adv_params_cp.max_interval = htobs(0x0800);
	my_advertise_param->adv_params_cp.chan_map = 7;
	
	my_advertise_param->adv_params_rq = ble_hci_request(
		OCF_LE_SET_ADVERTISING_PARAMETERS,
		LE_SET_ADVERTISING_PARAMETERS_CP_SIZE, &my_advertise_param->status, &my_advertise_param->adv_params_cp);
	
	my_advertise_param->ret = hci_send_req(my_advertise_param->device, &my_advertise_param->adv_params_rq, 1000);
	if ( my_advertise_param->ret < 0 ) {
		hci_close_dev(my_advertise_param->device);
		perror("Failed to set advertisement parameters data.");
		return 0;
	}
}

void* advertise(void* my_advertise_param1) { 
	struct advertise_param* my_advertise_param = (struct advertise_param*) my_advertise_param1;

	t3 = clock();
	char* input_char;
	int count = 0;
	int sequence = 0;
	uint8_t mac[6]; 
	for ( int i = 0; i < 6; i++ )
		mac[i] = mac_reader[6 - i - 1];
	
	for ( int i = 0; i < 5; ++i ) {
		count = 0;
		sequence = 0;
		while ( count < msg_to_reader.size() ) {
			string sub_input;
			if ( count == 0 ) {
				stringstream ss;

				for ( int i = 5; i >= 0; --i  ) {
					sub_input += (char)mac[i];
				}
				
				ss << sequence;
				sub_input += ss.str();

				char len_p;
				len_p = msg_to_reader.size();
				//cout << "len_p:" << len_p << endl;
				sub_input += len_p;
				if ( msg_to_reader.size() >= 18 ) {
					sub_input += msg_to_reader.substr(0,18);
					count += 18;
				}
				else {
					sub_input += msg_to_reader.substr(0);
					count += msg_to_reader.size();
				}
				cout << "\nadvertise msg:\n" << "\n";
				cout << sub_input << "\n";


			}
			else {
				for ( int i = 5; i >= 0; --i  ) {
					sub_input += (char)mac[i];
				}
				stringstream ss;
				ss << sequence;
				sub_input += ss.str();
				if ( msg_to_reader.size() - count < 19 ) {
					printf("\nit is the last packet in advertise........\n");
					sub_input += msg_to_reader.substr( count );
					count += msg_to_reader.size();
				}
				else {
					sub_input += msg_to_reader.substr( count,19 );
					count += 19;
				}
				cout << "\nadvertise msg:\n" << "\n";
				cout << sub_input << "\n";
			}

			
			input_char = new char[sub_input.size() + 1];
			memcpy(input_char, sub_input.c_str(), sub_input.size() + 1);
			
			my_advertise_param->adv_data_cp = ble_hci_params_for_set_adv_data(input_char);
			my_advertise_param->adv_data_rq = ble_hci_request(
				OCF_LE_SET_ADVERTISING_DATA,
				LE_SET_ADVERTISING_DATA_CP_SIZE, &my_advertise_param->status, &my_advertise_param->adv_data_cp);

			my_advertise_param->ret = hci_send_req(my_advertise_param->device, &my_advertise_param->adv_data_rq, 1000);
			if ( my_advertise_param->ret < 0 ) {
				hci_close_dev(my_advertise_param->device);
				perror("Failed to set advertising data.");
				return 0;
			}

			// Enable advertising.

			memset(&my_advertise_param->advertise_cp, 0, sizeof(my_advertise_param->advertise_cp));
			my_advertise_param->advertise_cp.enable = 0x01;

			my_advertise_param->enable_adv_rq = ble_hci_request(
				OCF_LE_SET_ADVERTISE_ENABLE,
				LE_SET_ADVERTISE_ENABLE_CP_SIZE, &my_advertise_param->status, &my_advertise_param->advertise_cp);

			my_advertise_param->ret = hci_send_req(my_advertise_param->device, &my_advertise_param->enable_adv_rq, 1000);
			if ( my_advertise_param->ret < 0 ) {
				hci_close_dev(my_advertise_param->device);
				perror("Failed to enable advertising.");
				return 0;
			}
			
			sub_input.clear();
			sequence += 1;
			delete [] input_char;
			sleep(1);
		}
	}
	t4 = clock();
	printf("\n-----------------------\n");
	printf("\nadvertise total time = %lf\n", (double)(t4 - t3)/CLOCKS_PER_SEC);
	printf("\n-----------------------\n");
	pthread_exit(0);
}

void close_advertise(struct advertise_param* my_advertise_param) {
	hci_close_dev(my_advertise_param->device);
}

bool if_mac_check( uint8_t *receive_packet ) {
	if ( receive_packet[19] == 0xB8 && receive_packet[20] == 0x27 
	&& receive_packet[21] == 0xEB && receive_packet[22] == 0xFC 
	&& receive_packet[23] == 0x24 && receive_packet[24] == 0x91
	&& receive_packet[7] == 0x26 && receive_packet[8] == 0xBA 
	&& receive_packet[9] == 0xAB && receive_packet[10] == 0xEB
	&& receive_packet[11] == 0x27 && receive_packet[12] == 0xB8 ) {
		return true;
	}
	
	return false;
}

int set_packet_count(int msg_length) {
	if (msg_length <= 18) {
		packet_count = 1;   
		return packet_count;
	}
	else {
		packet_count = 1 + ceil((float)(msg_length - 18)/19);
		return packet_count;
	}
	
	return 0;
}

void set_msg_get(int if_first_packet, uint8_t* buf) {

	if (if_first_packet == true) {
		int begin_count = 27;
		int index_count = 0;
		if ((int)buf[25]-48+1 == packet_count) {
			while (index_count < msg_length) {
				msg_get[index_count] = buf[begin_count++];
				++index_count;
			}
		}
		else {
			while ( index_count < 18  ) {
				msg_get[index_count] = buf[begin_count++];
				++index_count;
			}
		}
	}
	else {
		int begin_count = 26;
		int index_count = 0;
		int index_in_arr = 18 + ((int)buf[25] - 48 - 1)*19;
		
		if ((int)buf[25] - 48 + 1 == packet_count) {
			printf( "\nit is the last packet\n");
			while (index_in_arr < msg_length) {
				msg_get[index_in_arr] = buf[begin_count];
				++begin_count;
				++index_in_arr;
			}		
			
		}
		else {
			printf("\n(int)buf[25]-48-1*19 = %d\n", ((int)buf[25]-48-1)*19);
			
			while (index_count < 19) {
				msg_get[index_in_arr] = buf[begin_count];
				index_count++;
				begin_count++;
				++index_in_arr;

			}
		}
	}
}

void print_msg_get() {
	int j = 0;
	for (j = 0; j < msg_length; ++j) {
		printf("%02x ", msg_get[j]);
	}
	printf("\n");
}

bool if_count_bit_full ( bool* count_bit, int len ) {
	int count = 0;

	for ( int i = 0; i < len; ++i ) {
		if ( count_bit[i] == true )
			count++;
		if ( count == len ) {
			return true;
		}
	}

	return false;

}

void encrypt() {
	printf("encrypt .......\n");
	string input_string;
	for ( int j = 0; j < msg_length; j++ ) {
		input_string += (char)msg_get[j];
		printf( "%d > %c\n",j ,(char)msg_get[j] );
	}
	
	input_string[input_string.size() - 1] = (char)(input_string[input_string.size() - 1] | LN1[3]);
	input_string[input_string.size() - 2] = (char)(input_string[input_string.size() - 2] | LN1[2]);
	input_string[input_string.size() - 3] = (char)(input_string[input_string.size() - 3] | LN1[1]);
	input_string[input_string.size() - 4] = (char)(input_string[input_string.size() - 4] | LN1[0]);
	
	//vector<uint8_t> mVector(input_string.begin(),input_string.end());
	//uint8_t *p = &mVector[0];
	string sha1256 = hmacHex( "ABCD",input_string );
	for ( int i = 0; i < 32; ++i ) {
		msg_to_reader += ( sha1256[i*2] << 4 ) | ( sha1256[i*2 + 1] ); 
	}
	
	printf("encrypt done.......\n");
}