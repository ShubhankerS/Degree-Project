#include <iostream> 
#include <thread> 
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <ctime>
#include <stdint.h>
#include <cstdlib>
#include <sstream>
#include <queue> 
#include <stdio.h>
#include <time.h>   
#include <thread>
#include <chrono> 
#include <cstring>
#include <iomanip>
#include <map>
#include <iterator>
#include <time.h> 
#include <algorithm> 
#include <chrono>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <fstream>
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), connect(), sendto(), and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */

using namespace std::chrono; 

static const char alphanum[] =
"0123456789"
// "!@#$%^&*"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz";

int stringLength = sizeof(alphanum) - 1;

char genRandom()
{

    return alphanum[rand() % stringLength];
}

std::string random_key_gen(){
    srand(time(0));
    std::string Str;
    for(unsigned int i = 0; i < 64; ++i)
    {
        Str += genRandom();
    }
    // cout << Str << endl;

    return Str;
}

unsigned int RandomNoGen(int n5)
{
    static unsigned int seed;
    int rndno;
    srand(time(NULL));
    rndno = rand();
    seed = rndno * seed + rndno + n5;
 
    return seed %100000000;
}

std::string sha256(const std::string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void errno_abort(const char* header)
{
    perror(header);
    exit(EXIT_FAILURE);
}

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);

	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, strlen(b64message));


    assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(bio);

	return (0); //success
}

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text=(*bufferPtr).data;

	return (0); //success
}

std::string sign(std::string privkey, std::string hash)
{

    //Checking if the private key is correct and loaded
    FILE *fp;

    fp = fopen(privkey.c_str(), "r");
    if (!fp) {
        std::cout<<"Private key not loaded";
        // return -1;
    }

    
    EC_KEY *privatekey; 
    privatekey = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    if (!privatekey) {
        ERR_print_errors_fp(stderr);
        // return -1;
    }

    // validate the key
    EC_KEY_check_key(privatekey);

    EVP_PKEY *evp_sign_key;
    evp_sign_key = EVP_PKEY_new();

    int ret;

    ret = EVP_PKEY_assign_EC_KEY(evp_sign_key, privatekey);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        // return -1;
    }

    fclose(fp);

   // std::cout << "Private key ok" << std::endl << std::endl;


    //Signing part starts here....
    
    const unsigned char *hh = reinterpret_cast<const unsigned char *>(hash.c_str());

    unsigned char *buffer, *sig;
    unsigned int buf_len;
    buf_len = ECDSA_size(privatekey);
    void *memadrs = buffer;
    memadrs = OPENSSL_malloc(buf_len);
    sig = (unsigned char *)memadrs;

    int i = ECDSA_sign(0, hh, 32, sig, &buf_len, privatekey);

    if (i==1){
    //cout<<"Signature generated: "<<sig<<endl;   //signature is DER encoded
    }

        
    //Converting DER encoded to base64
    char* base64EncodeOutput;
    Base64Encode(sig, buf_len, &base64EncodeOutput);
    //cout<<endl<<"Base64 output = "<<base64EncodeOutput<<endl;
      
    return base64EncodeOutput;
}

std::string HMAC256(std::string data, std::string key)
{       
        std::stringstream ss;
        HMAC_CTX *h = HMAC_CTX_new();
        unsigned int  len;
        unsigned char out[EVP_MAX_MD_SIZE];
        HMAC_Init_ex(h, key.c_str(), key.length(), EVP_sha256(), NULL);
        HMAC_Update(h, (unsigned char*)data.c_str(), data.length());
        HMAC_Final(h, out, &len);
        HMAC_CTX_free(h); 
        for (unsigned int i = 0;  i < len;  i++)
        {
          ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int> (out[i]);
        }
        return ss.str();
}


std::string token_with_key(int n1, std::string hh){                   //n1 is vehicle number and counter is to check the hash count
    int r;
    r = RandomNoGen(n1);      //For ID

    time_t currentTime = time(0);
    std::string ct = std::to_string(currentTime);                 //convert current time to string

    std::string rr = std::to_string(r);                 //convert rnd no. to string
    std::string nn = std::to_string(n1);                 //convert vehicle no. to string
    
    //Reading the Tesla Key file for getting the original key
    std::string line5;
    std::ifstream myfile5 ("V" + nn  + " TeslaKeys");
    std::string a5;

    if (myfile5.is_open())
    {
        while ( getline (myfile5,line5) )
        {
            a5 = line5;
        }
    myfile5.close();
    }
    
    std::string text_to_sign = rr + "||STATUS||" + ct + "||" + a5 + "||" + hh;
    

    //SIGNING the message.....

    //Hash generation
    std::string h;
    h = sha256(text_to_sign);
    // std::cout<<"Hash generated: "<<h<<std::endl<<std::endl;

    std::string b64 = sign("V" + nn + " Privkey", h);
    std::string b = b64.substr(0,96);

    text_to_sign = text_to_sign + "||" + b + "||" + h;              //adding sign and hash to the text

    //Adding message with signature......

    //Reading the signed_PC file
    std::string line1;
    std::ifstream myfile1 ("V" + nn + " signed_PC");
    std::string a1;
    if (myfile1.is_open())
    {
        while ( getline (myfile1,line1) )
        {
            a1 = a1 + line1;
        }
    myfile1.close();
    }

    std::string fmsg = text_to_sign + "||" + a1;

    //Final message with attached TESLA MAC...
    std::string hash_of_this_key = HMAC256(a5, "RANDOM KEY");

    std::string g = HMAC256(fmsg,hash_of_this_key);             //should be key and not hash of key...CHANGE LATER!

    fmsg = fmsg + "||" + g;
    return fmsg;
}


std::string token(int n1, int counter, int kl, std::string hh, int i4){                   //n1 is vehicle number and counter is to check the hash count
    int r;
    r = RandomNoGen(n1);      //For ID

    time_t currentTime = time(0);
    std::string ct = std::to_string(currentTime);                 //convert current time to string

    std::string rr = std::to_string(r);                 //convert rnd no. to string
    std::string nn = std::to_string(n1);                 //convert vehicle no. to string
    

    std::string line;

    std::ifstream myfile ("V" + nn  + " TeslaKeys");
    std::string a;
    std::string a5;

    if (myfile.is_open())
    {
      for (int lineno = 1; getline (myfile,line) && lineno < kl; lineno++){
        if (lineno == i4)
        a = line;
        if (lineno == (i4+1))
        a5 = line;

      }
      
    myfile.close();
    }

    std::string text_to_sign = rr + "||STATUS||" + ct + "||" + a + "||" + hh;
 
        

    //SIGNING the message.....

    //Hash generation
    std::string h;
    h = sha256(text_to_sign);
    // std::cout<<"Hash generated: "<<h<<std::endl<<std::endl;

    std::string b64 = sign("V" + nn + " Privkey", h);
    std::string b = b64.substr(0,96);

    text_to_sign = text_to_sign + "||" + b + "||" + h;              //adding sign and hash to the text

    //Adding message with signature......

    //Reading the signed_PC file
    std::string line1;
    std::ifstream myfile1 ("V" + nn + " signed_PC");
    std::string a1;
    if (myfile1.is_open())
    {
        while ( getline (myfile1,line1) )
        {
            a1 = a1 + line1;
        }
    myfile1.close();
    }

    std::string fmsg = text_to_sign + "||" + a1;

    //Final message with attached TESLA MAC...
    std::string hash_of_this_key = HMAC256(a5, "RANDOM KEY");
    std::string g = HMAC256(fmsg,hash_of_this_key);             //should be key and not hash of key...CHANGE LATER!

    fmsg = fmsg + "||" + g;
    return fmsg;
}


int verify_pc(std::string pubkey, std::string enc, std::string hash){
//CHECKING THE PUBLIC KEY
    FILE *fp;

    // load in the keys
    fp = fopen(pubkey.c_str(), "r");
    if (!fp) {
        return -1;
    }
    
    EC_KEY *publickey; 

    publickey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    if (!publickey) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    EVP_PKEY *evp_verify_key;

    evp_verify_key = EVP_PKEY_new();

    int ret1;

    ret1 = EVP_PKEY_assign_EC_KEY(evp_verify_key, publickey);
    if (ret1 != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    fclose(fp);

    // std::cout << "Public key ok" << std::endl<<std::endl;



    //Decoding base64

    unsigned char* base64DecodeOutput;

    size_t len1;

    
    std::string enctext1 = enc.substr(0,96);
    char * enctext = (char *)(enctext1.c_str());

    Base64Decode(enctext, &base64DecodeOutput, &len1);
    // std::cout<<"Decoded: "<<base64DecodeOutput<<std::endl;
   
    


   //Verifying part starts here.....

    const unsigned char *hh = reinterpret_cast<const unsigned char *>(hash.c_str());
    // std::cout<<"hash = "<<hh<<std::endl;
    int ret5 = ECDSA_verify(0, hh, 32, base64DecodeOutput, len1, publickey);
     if (ret5 == 1) {
    // std::cout<<"Pseudonym Signature OK (PC Verified)!! ";
    } else if (ret5 == 0) {
    std::cout<<"Incorrect Pseudonym Signature! ";
    } else {
    std::cout<<"ERROR!! ";
    }
 

    return ret5;
}

int verify_message(std::string pubkey, std::string enc, std::string hash){
//CHECKING THE PUBLIC KEY
    FILE *fp;

    // load in the keys
    fp = fopen(pubkey.c_str(), "r");
    if (!fp) {
        return -1;
    }

    EC_KEY *publickey; 

    publickey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    if (!publickey) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_PKEY *evp_verify_key;

    evp_verify_key = EVP_PKEY_new();

    int ret1;

    ret1 = EVP_PKEY_assign_EC_KEY(evp_verify_key, publickey);
    if (ret1 != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    fclose(fp);

    // std::cout << "Public key ok" << std::endl<<std::endl;



    //Decoding base64

    unsigned char* base64DecodeOutput;

    size_t len1;

    
    std::string enctext1 = enc.substr(0,96);
    char * enctext = (char *)(enctext1.c_str());

    Base64Decode(enctext, &base64DecodeOutput, &len1);
    // std::cout<<"Decoded: "<<base64DecodeOutput<<std::endl;
   
    


   //Verifying part starts here.....

    const unsigned char *hh = reinterpret_cast<const unsigned char *>(hash.c_str());
    

    int ret5 = ECDSA_verify(0, hh, 32, base64DecodeOutput, len1, publickey);
     if (ret5 == 1) {
    // std::cout<<"Message Signature OK ";
    } else if (ret5 == 0) {
    std::cout<<"Incorrect Message Signature! ";
    } else {
    std::cout<<"ERROR!! ";
    }
 

    return ret5;
}


int verify_tesla_key(std::string str, std::string key){
   
    std::string h = sha256(key);
    int i;
    while(1){
        label2:
        if (str == h || str == key){
            // std::cout<<std::endl<<"TESLA_KEY Verified for previous beacon"<<std::endl;
            i = 1;
            goto label1;
        }else if(str != h || str != key){
            h = sha256(h);
            goto label2;
        } else {
            std::cout<<std::endl<<"TESLA KEY Verification FAILED!!!"<<std::endl;
            i = 0;
        }
    }

label1:
    return i;
}

std::map<std::string, int>::iterator serachByValue(std::map<std::string, int> & keylist, int val)
{
    // Iterate through all elements in std::map and search for the passed element
    std::map<std::string, int>::iterator it = keylist.begin();
    while(it != keylist.end())
    {
        if(it->second == val)
        return it;
        it++;
    }
}

int processing_data(std::string a, int n){

	std::string arr[14] = {};			//depends on how many fields in the message
	int count = 0;

	//Spliting received data........
    std::string delimiter = "||";
    size_t pos = 0;
    std::string token;
    while ((pos = a.find(delimiter)) != std::string::npos) {
    token = a.substr(0, pos);
    // std::cout << token << std::endl;            //shows all split data except the last one.
	arr[count] = token;
    a.erase(0, pos + delimiter.length());
	count++;
    }
	// std::cout << arr[5];

    // std::cout << a << std::endl<<std::endl;         //a is the last value in the split_message
    std::string nn = std::to_string(n);                 //convert vehicle no. to string

	//Verifying the PC signature.....
	int ii1 = verify_pc("CApubkey", arr[11], arr[12]);               //arr[12] is ca_hash and arr[11] is ca_sign


    // //Verifying the attached TESLA KEY.....
    // int ii2 = verify_tesla_key(arr[3]);

    

	//Writing the received public on a file
    std::ofstream oo;
    oo.open(+"received_pubkey_v"+nn);
    //write on the file
	oo<<"-----BEGIN PUBLIC KEY-----"<<std::endl;
    oo<<arr[8]<<std::endl;                      //arr[8] is public key
	oo<<"-----END PUBLIC KEY-----";
    //close the file
    oo.close();

	std::string s5 = arr[5];                    //arr[5] is encoded signature

	std::cout<<std::endl;

	//Verifying the received public key......
	int ii2 = verify_message("received_pubkey_v"+nn, s5, arr[6]);         //arr[6] is message_hash
    
    int ii3;

    if(ii1==1 && ii2==1)
    ii3 = 1;
	
    // return ii3;
    return ii3;
}

std::string check_PC_ID(std::string chk){
    std::string arr1[14] = {};			//depends on how many fields in the message
	int count1 = 0;

	//Spliting received data........
    std::string delimiter = "||";
    size_t pos = 0;
    std::string token;
    while ((pos = chk.find(delimiter)) != std::string::npos) {
    token = chk.substr(0, pos);
    // std::cout << token << std::endl;
	arr1[count1] = token;
    chk.erase(0, pos + delimiter.length());
	count1++;
    }

    return arr1[7];
}

std::string get_beacon(std::string a){
    std::string arr[14] = {};			//depends on how many fields in the message
	int count = 0;

	//Spliting received data........
    std::string delimiter = "||";
    size_t pos = 0;
    std::string token;
    while ((pos = a.find(delimiter)) != std::string::npos) {
    token = a.substr(0, pos);
    // std::cout << token << std::endl;            //shows all split data except the last one.
	arr[count] = token;
    a.erase(0, pos + delimiter.length());
	count++;
    }
    return arr[0]+"||"+arr[1]+"||"+arr[2]+"||"+arr[3]+"||"+arr[4]+"||"+arr[5]+"||"+arr[6]+"||"+arr[7]+"||"+arr[8]+"||"+arr[9]+"||"+arr[10]+"||"+arr[11]+"||"+arr[12];
}

std::string get_beacon_id(std::string a){
    std::string arr[14] = {};			//depends on how many fields in the message
	int count = 0;

	//Spliting received data........
    std::string delimiter = "||";
    size_t pos = 0;
    std::string token;
    while ((pos = a.find(delimiter)) != std::string::npos) {
    token = a.substr(0, pos);
    // std::cout << token << std::endl;            //shows all split data except the last one.
	arr[count] = token;
    a.erase(0, pos + delimiter.length());
	count++;
    }
    return arr[0];
}

std::string get_coophash(std::string a){
    std::string arr[14] = {};			//depends on how many fields in the message
	int count = 0;

	//Spliting received data........
    std::string delimiter = "||";
    size_t pos = 0;
    std::string token;
    while ((pos = a.find(delimiter)) != std::string::npos) {
    token = a.substr(0, pos);
    // std::cout << token << std::endl;            //shows all split data except the last one.
	arr[count] = token;
    a.erase(0, pos + delimiter.length());
	count++;
    }
    return arr[4];
}

std::string get_mac(std::string a){
    std::string arr[14] = {};			//depends on how many fields in the message
	int count = 0;

	//Spliting received data........
    std::string delimiter = "||";
    size_t pos = 0;
    std::string token;
    while ((pos = a.find(delimiter)) != std::string::npos) {
    token = a.substr(0, pos);
    // std::cout << token << std::endl;            //shows all split data except the last one.
	arr[count] = token;
    a.erase(0, pos + delimiter.length());
	count++;
    }
    return a;
}

int mac_check(std::string str1, std::string key, std::string beacon)
{
    int i;
    std::string g = HMAC256(beacon, key);
    if (str1 == g){
        // std::cout<<"TESLA MAC Verified";
        i = 1;
    } else
    {
        // std::cout<<"TESLA MAC Verification Failed"<<std::endl;
        // std::cout<<str1<<std::endl<<g;
        i = 0;
    }
    
    return i;
}

int mac_check_loop(std::string m){
    std::string h = sha256("cached key");
    int j;

    while(1){
        h = sha256(h);
        std::string s = HMAC256(h, "RANDOM KEY");
        j = mac_check(get_mac(m), s, get_beacon(m));
        if(j==1)
        goto l9;
    }

    l9:
    return j;
}
std::string get_key(std::string a){
    std::string arr[14] = {};			//depends on how many fields in the message
	int count = 0;

	//Spliting received data........
    std::string delimiter = "||";
    size_t pos = 0;
    std::string token;
    while ((pos = a.find(delimiter)) != std::string::npos) {
    token = a.substr(0, pos);
    // std::cout << token << std::endl;            //shows all split data except the last one.
	arr[count] = token;
    a.erase(0, pos + delimiter.length());
	count++;
    }
    return arr[3];
}

void showq(std::queue <std::string> gq) 
            { 
                std::queue <std::string> g = gq; 
                while (!g.empty()) 
                { 
                    std::cout << '\t' << g.front(); 
                    std::cout<<std::endl;
                    g.pop(); 
                } 
                std::cout << '\n'; 
            } 


int received_data(std::string str, int n1){
    std::string c = check_PC_ID(str);
    int i1;

    //Following is to show what is neccesary and no repetition of own sent beacon....
    if((n1==1 && c != "10089849") || (n1==2 && c != "79398310") || (n1==3 && c != "87364828") || (n1==4 && c != "52036563"))            //Don't show own send messages by checking PC_ID
    {                                               //this means v1 will receive everything except it's own pc. same for v2, v3, v4.....
        
        std::cout<<std::endl<<"RECEIVED:     "<<str;
        std::cout<<std::endl;

        // i1 = processing_data(str, n1);
        i1 = 1;
    }
        
    return i1;
}

std::string check_same_beacon_id(std::string a){
    std::string arr[14] = {};			//depends on how many fields in the message
	int count = 0;

	//Spliting received data........
    std::string delimiter = "||";
    size_t pos = 0;
    std::string token;
    while ((pos = a.find(delimiter)) != std::string::npos) {
    token = a.substr(0, pos);
    // std::cout << token << std::endl;            //shows all split data except the last one.
	arr[count] = token;
    a.erase(0, pos + delimiter.length());
	count++;
    }
    return arr[0];
}


std::map<std::string, int> sendinghashlist;
std::map<std::string, int> storedhashlist;


//BROADCASTING...
void sending(int n1) 
{ 	      
 here1:
    int c1 =1;              //c1 is for counter till key_len messages and then delay
    int cc = 1;             //cc is the counter to know when a new key is required on the key_length' message
    int key_len = 3000;
    std::string m;
    int n3 = 1;             //n3 is the counter to read the particular line from the tesla key file
label:
    std::string h;
    if(sendinghashlist.empty())
    h = "NULL";             //h is the cooperative hash that is sent
    else
    {

        std::map<std::string, int>::iterator it = sendinghashlist.begin();
        h = it->first;

        sendinghashlist.erase(it);
     
    }

    if(cc == key_len)
    m= token_with_key(n1, h);
    else{
        m = token(n1, cc, key_len, h, n3);
        n3++;
    }

    cc++;
    const char *aa = reinterpret_cast<const char *>(m.c_str());

#define SERVERPORT 9999
    struct sockaddr_in send_addr, recv_addr;
    int trueflag = 1, count = 0;
    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        errno_abort("socket");
#ifndef RECV_ONLY
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
                   &trueflag, sizeof trueflag) < 0)
        errno_abort("setsockopt");

    memset(&send_addr, 0, sizeof send_addr);
    send_addr.sin_family = AF_INET;
    send_addr.sin_port = (in_port_t) htons(SERVERPORT);
    // broadcasting address for unix (?)
    inet_aton("255.255.255.255", &send_addr.sin_addr);
    // inet_aton("127.0.0.1", &send_addr.sin_addr);
    // send_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
#endif // ! RECV_ONLY
    // std::this_thread::sleep_for(std::chrono::seconds(3));                   //delay before sending first beacon
	
   
#ifndef RECV_ONLY
        
        char sbuf[100000] = {};                                    //CHANGE the number according to the length of the string
        snprintf(sbuf, sizeof(sbuf), aa, count++);
        if (sendto(fd, sbuf, strlen(sbuf)+1, 0,
                   (struct sockaddr*) &send_addr, sizeof send_addr) < 0)
            errno_abort("send");
        printf("SEND: %s\n", sbuf);

         //random number generator not fast enough if the delay is too less.
        usleep(100000);                           //time delay of 0.1 second between two messages, meaning 10 messages every 1 second
        // usleep(1000000);                           //testing

    //    if (c1%10 == 0)
        // std::this_thread::sleep_for(std::chrono::seconds(3));           //time delay between every 10 messages

       if (c1==key_len){        
            // exit(0);                            //exit after key_len messages
            std::this_thread::sleep_for(std::chrono::seconds(5));           //time delay between every key_len messages
            goto here1;                             //start the process again
        }
        c1++;
#endif // ! RECV_ONLY
        
    close(fd);
    goto label;
} 

//RECEIVING BROADCAST MEASSAGES....
void receiving(int n) 
{ 
    std::string nn = std::to_string(n);                 //convert vehicle no. to string

  std::map<std::string, int> pclist;
  std::map<std::string, int> keylist;
  std::map<std::string, int> beaconlist;
  std::map<std::string, int> acceptedBeacon;

	#define SERVERPORT 9999
    struct sockaddr_in send_addr, recv_addr;
    int trueflag = 1, count = 0;
    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        errno_abort("socket");

#ifndef SEND_ONLY
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                   &trueflag, sizeof trueflag) < 0)
        errno_abort("setsockopt");

    memset(&recv_addr, 0, sizeof recv_addr);
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = (in_port_t) htons(SERVERPORT);
    recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr*) &recv_addr, sizeof recv_addr) < 0)
        errno_abort("bind");

#endif // ! SEND_ONLY

    
    int i5, i7, i9, i2;
    int ii = 1;                             //count for pclist
    int iii = 1;                            //count for acceptedBeacon
    int count_for_check = 1;                //counter for every 5th beacon to be signature verified 
    int adder = 0;
    // int i4 = 1;                             //counter for the time list
    // int i6 = 1;                             //counter for number of beacons

    std::string cbh;
while ( 1 ) {
    #ifndef SEND_ONLY
        char rbuf[100000] = {};   
        if (recv(fd, rbuf, sizeof(rbuf)-1, 0) < 0)
            errno_abort("recv");

        auto start1 = high_resolution_clock::now(); 
        auto start = high_resolution_clock::now(); 

        i5 = received_data(rbuf, n);
        if(i5 == 1){
            std::string c = check_PC_ID(rbuf);
            if (pclist.find(c) == pclist.end()){        //if pc is not in the list
                i7 = processing_data(rbuf, n);          //verify the first received message
                if (i7==1){
                    std::cout<<"PC and Message Signature Verified";
                    std::cout<<std::endl<<"Beacon Accepted"<<std::endl;
                    count_for_check++;

                    auto stop1 = high_resolution_clock::now();
                    auto duration1 = duration_cast<microseconds>(stop1 - start1); 

                    //Writing the received public on a file
                    std::ofstream oo1;
                    oo1.open(+"S3 Time per beacon V" + nn, std::ios_base::app);        
                    //write on the file
                    oo1<<duration1.count()<<std::endl;                      
                    //close the file
                    oo1.close();
                    acceptedBeacon.insert(std::make_pair(rbuf, iii));

                    // the hash of every accepted beacon goes into the hashlist so that this coud be send in the next broadcast
                    sendinghashlist.insert(std::make_pair(sha256(rbuf), iii));
                    storedhashlist.insert(std::make_pair(sha256(rbuf), iii));

                    iii++;
                }

                pclist.insert(std::make_pair(c, ii));               //stores the pc in the map(list).
                ii++;

            }
            else
            {   

                int bid = stoi(get_beacon_id(rbuf));
                keylist.insert(std::make_pair(get_key(rbuf), bid));
                beaconlist.insert(std::make_pair(rbuf, bid));
                std::cout<<std::endl;

                if(count_for_check % (5+adder) == 0){
                    i2 = processing_data(rbuf, n);
                    if (i2==1){
                        std::cout<<"PC and Message Signature Verified";
                        std::cout<<std::endl<<"Beacon Accepted"<<std::endl;
                        count_for_check++;

                        auto stop11 = high_resolution_clock::now();
                        auto duration11 = duration_cast<microseconds>(stop11 - start1); 

                        //Writing the received public on a file
                        std::ofstream oo1;
                        oo1.open(+"S3 Time per beacon V" + nn, std::ios_base::app);        
                        //write on the file
                        oo1<<duration11.count()<<std::endl;                      
                        //close the file
                        oo1.close();

                        acceptedBeacon.insert(std::make_pair(rbuf, iii));

                        // // the hash of every accepted beacon goes into the hashlist so that this coud be send in the next broadcast
                        sendinghashlist.insert(std::make_pair(sha256(rbuf), iii));
                        storedhashlist.insert(std::make_pair(sha256(rbuf), iii));
                        adder = 0;
                        iii++;
                        goto here5;
                    }
                }
                if(keylist.find(sha256(get_key(rbuf))) != keylist.end() || keylist.find(sha256(sha256(get_key(rbuf)))) != keylist.end())
                {
                    std::map<std::string, int>::iterator it1 = keylist.find(sha256(get_key(rbuf)));
                    // std::map<std::string, int>::iterator it2 = keylist.find(sha256(sha256(get_key(rbuf))));

                    std::cout<<std::endl<<"Tesla Key verified for beacon ID: "<<it1->second;
                    keylist.erase(it1);
                    

                    std::map<std::string, int>::iterator it2 = serachByValue(beaconlist, it1->second);
                    //it2->first is the beacon under verification
                    i9 = mac_check(get_mac(it2->first), HMAC256(get_key(rbuf), "RANDOM KEY"), get_beacon(it2->first));
                    if (i9==1)
                    {
                        std::cout<<std::endl<<"Tesla MAC Verified for beacon ID: "<<it2->second;
                        std::cout<<std::endl<<"Beacon Accepted"<<std::endl;

                        auto stop111 = high_resolution_clock::now();
                        auto duration111 = duration_cast<microseconds>(stop111 - start1); 

                        //Writing the received public on a file
                        std::ofstream oo1;
                        oo1.open(+"S3 Time per beacon V" + nn, std::ios_base::app);        
                        //write on the file
                        oo1<<duration111.count()+1000<<std::endl;                      
                        //close the file
                        oo1.close();
                    
                        acceptedBeacon.insert(std::make_pair(rbuf, iii));
                        sendinghashlist.insert(std::make_pair(sha256(rbuf), iii));
                        storedhashlist.insert(std::make_pair(sha256(rbuf), iii));

                        count_for_check++;
                        
                        iii++;

                        beaconlist.erase(it2);
                    }

                }
            }
            
        }
        here5:
            printf("\n");
    
#endif // ! SEND_ONLY
    }
    close(fd);
}


int main(int argc, char **argv) 
{  
    int n = atoi(argv[1]);
    std::thread th1(sending, n);

	std::thread th2(receiving, n); 

	th1.join(); 

	// Wait for thread t2 to finish 
	th2.join(); 

	return 0; 
} 
