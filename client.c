# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <string.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <netdb.h>
# include <stdbool.h>
# include <time.h>
# include <sys/select.h>
# include <unistd.h>
# include <pthread.h>
# include <signal.h>

// pdu types
# define REGISTER_REQ (unsigned char) 0x00
# define REGISTER_ACK (unsigned char) 0x02
# define REGISTER_REJ (unsigned char) 0x06
# define REGISTER_NACK (unsigned char) 0x04
# define ERROR (unsigned char) 0x0F

# define ALIVE_INF (unsigned char) 0x10
# define ALIVE_ACK (unsigned char) 0x12
# define ALIVE_NACK (unsigned char) 0x14
# define ALIVE_REJ (unsigned char) 0x16

# define SEND_FILE (unsigned char) 0x20
# define SEND_DATA (unsigned char) 0x22
# define SEND_ACK (unsigned char) 0x24
# define SEND_END (unsigned char) 0x2A

# define GET_FILE (unsigned char) 0x30
# define GET_DATA (unsigned char) 0x32
# define GET_ACK (unsigned char) 0x34
# define GET_END (unsigned char) 0x3A

// Register configuration
# define SEND_INTERVAL 1        // t
# define PACKAGES_FOR_INC 2     // p
# define MAX_INTERVAL 3         // q*t
# define WAIT_TIME 2            // u
# define MAX_PACKAGES 6         // n
# define MAX_ATTEMPTS 2         // o

// Alive configuration
# define ALIVE_FREQUENCY 2      // r
# define MAX_NON_RECEIBED_ACK 3 // s

// TCP configuration
# define MAX_TCP_TIME 3         // w

struct client_data {
    char id[7];
    char mac[13];
    char nms_id[20];
    int port;
};

struct server_data {
    char id[7];
    char mac[13];
    char rand_num[7];
};

struct package {
    unsigned char type;
    char id[7];
    char mac[13];
    char random_number[7];
    char data[50];
};

struct file_package {
    unsigned char type;
    char id[7];
    char mac[13];
    char random_number[7];
    char data[150];
};

struct server {
    char *address;
};

struct registration_values {
    int send_time;
    int sent_packages;
    int registration_process;
};

struct tcp_socket {
    int socket;
    int ip;
    int port;
    struct sockaddr_in address;
};

enum client_states {
    DISCONNECTED,
    WAIT_REG_RESPONSE,
    REGISTERED,
    SEND_ALIVE
};

struct client_data client_d;
struct server_data server_d;
struct server server;
struct sockaddr_in udp_address;
struct registration_values reg_values;
struct tcp_socket tcp_sock;
enum client_states state = DISCONNECTED;
char *states_name[] = {"DISCONNECTED", "WAIT_REG_RESPONSE", "REGISTERED", "SEND_ALIVE"};
char *file_name;
char *conf_file_name;
int sock;
bool debug = false;
pthread_t thread = (pthread_t) NULL;

void finalize_client();
void error_message(char *message);
void warning_message(char *message);
void debug_message(char *message);
void print_message(char *message);
void change_state(enum client_states stat);
void read_client_file();
void read_server_file();
void read_arguments();
void setup_udp_socket();
void setup_tcp_socket();
void setup_connection();
struct package build_conf_package();
void set_initial_values();
struct package *receive_package();
void init_loop();
void *manage_command_line();
void send_conf_file();
void get_conf_file();
struct file_package build_file_package(unsigned char type, char data[150]);
struct file_package build_empty_file_package();
void send_tcp_package(struct file_package pck);
struct file_package *recv_file_package();
char *read_console(int max_chars_to_read);
void send_alive();
struct package build_alive_package();
bool valid_server_data_udp(struct package *package);
bool valid_server_data_tcp(struct file_package *package);

int main(int argc, const char *argv[]) {
    signal(SIGINT, finalize_client);
    read_arguments(argc, argv);
    read_client_file();
    setup_udp_socket();
    setup_connection();
    init_loop();
}

void finalize_client() {
    print_message("Ending client");

    close(sock);
    free(file_name);
    free(conf_file_name);
    
    exit(0);
}

void error_message(char *message) {
    char *msg = "ERROR: ";
    char buffer[strlen(message) + strlen(msg)];

    sprintf(buffer, "%s%s", msg, message);
    print_message(buffer);
    exit(1);
}

void warning_message(char *message) {
    // Is like error_message function, but don't finish the program
    char *msg = "ERROR: ";
    char buffer[strlen(message) + strlen(msg)];

    sprintf(buffer, "%s%s", msg, message);
    print_message(buffer);
}

void debug_message(char *message) {
    char *msg = "DEBUG: ";
    char buffer[strlen(message) + strlen(msg)];
    
    sprintf(buffer, "%s%s", msg, message);
    print_message(buffer);
}

void print_message(char *message) {
    time_t t;
    struct tm *tm;
    char buffer[100];

    t = time(NULL);
    tm = localtime(&t);
    strftime(buffer, sizeof(buffer), "[%T]", tm);

    printf("%s:  =>  %s\n", buffer, message);
}

void print_send_message(struct package pck) {
    char buffer[200];
    
    sprintf(buffer, "Package sent:\n"
            "\t\t\tType: 0x%X,\n"
            "\t\t\tId: %s,\n "
            "\t\t\tMac: %s,\n"
            "\t\t\tRand num: %s,\n"
            "\t\t\tData: %s",
            (unsigned char) pck.type,
            pck.id, pck.mac,
            pck.random_number, pck.data);
    debug_message(buffer);
}

void change_state(enum client_states stat) {
    state = stat;

    char *msg = "State changed to ";
    char buffer[strlen(states_name[stat]) + strlen(msg)];
    sprintf(buffer, "%s%s", msg, states_name[stat]);
    
    print_message(buffer);

    if (state == DISCONNECTED) {
        exit(0);
    }
}

void read_client_file() {
    FILE* file = fopen(file_name, "r");
    if (file == NULL) {
        char *msg1 = "The file \"";
        char *msg2 = "\" doesn't exist";
        char buffer[strlen(msg1) + strlen(msg2) + strlen(file_name)];
        sprintf(buffer, "%s%s%s", msg1, file_name, msg2);
        error_message(buffer);
    }

    char line[50];
    char *token;

    while (fgets(line, sizeof(line), file) != NULL) {
        token = strtok(line, " ");

        if (strcmp(token, "Id") == 0) {
            token = strtok(NULL, " ");
            strncpy (client_d.id, token, sizeof(client_d.id) - 1);
        } else if (strcmp(token, "MAC") == 0) {
            token = strtok(NULL, " ");
            strncpy (client_d.mac, token, sizeof(client_d.mac) - 1);
        } else if (strcmp(token, "NMS-Id") == 0) { 
            token = strtok(NULL, " ");
            strncpy (client_d.nms_id, token, sizeof(client_d.nms_id));
            client_d.nms_id[strlen(client_d.nms_id) - 1] = '\0';
        } else if (strcmp(token, "NMS-UDP-port") == 0) {
            token = strtok(NULL, " ");
            client_d.port = atoi(token);
        }
    }

    fclose(file);
}

void read_arguments(int argc, char *argv[]) {
    file_name = malloc(sizeof("client.cfg"));
    conf_file_name = malloc(sizeof("boot.cfg"));
    strcpy(file_name, "client.cfg");
    strcpy(conf_file_name, "boot.cfg");
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            debug = true;
        } else if (strcmp(argv[i], "-c") == 0) {
            if (argc <= i + 1) {
                error_message("You have to specify the name of the file after '-c'");
            }
            i++;
            file_name = malloc(sizeof(argv[i + 1]));
            strcpy(file_name, argv[i]);
        } else if (strcmp(argv[i], "-f") == 0) {
            if (argc <= i + 1) {
                error_message("You have to specify the name of the file after '-f'");
            }
            i++;
            conf_file_name = malloc(sizeof(argv[i + 1]));
            strcpy(conf_file_name, argv[i]);
        }
    }
    
    if (debug) {debug_message("Arguments have been read");}
}

void setup_udp_socket() {
    struct hostent *host;
    struct sockaddr_in address;

    // Get hostent structure of server
    host = gethostbyname(client_d.nms_id);
    if (!host) {
        error_message("Could not find server");
    }

    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        error_message("Have been an error in the creation of the udp socket");
    }

    // Fill the structure with a local address
    memset(&address, 0, sizeof(struct sockaddr_in));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(0);

    // Bind
    if (bind(sock, (struct sockaddr *) &address, sizeof(struct sockaddr_in)) < 0) {
        error_message("Have been an error in the bind function");
    }

    // Fill the address structure
    memset(&udp_address, 0, sizeof(struct sockaddr_in));
    udp_address.sin_family = AF_INET;
    udp_address.sin_addr.s_addr = (((struct in_addr *) host->h_addr_list[0])->s_addr);
    udp_address.sin_port = htons(client_d.port);
}

void setup_tcp_socket() {
    struct hostent *host;

    // Get hostent structure of server
    host = gethostbyname(client_d.nms_id);
    if (!host) {
        error_message("Could not find server");
    }

    // Create TCP socket
    tcp_sock.socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock.socket < 0) {
        error_message("Have been an error in the creation of the tcp socket");
    }

    // Fill the address structure
    memset(&tcp_sock.address, 0, sizeof(struct sockaddr_in));
    tcp_sock.address.sin_family = AF_INET;
    tcp_sock.address.sin_addr.s_addr = (((struct in_addr *) host->h_addr_list[0])->s_addr);
    tcp_sock.address.sin_port = htons(tcp_sock.port);

    // Establish TCP connection
    if (connect(tcp_sock.socket, (struct sockaddr *) &tcp_sock.address, sizeof(tcp_sock.address)) < 0) {
        error_message("Could not connect TCP socket");
    }
}

void setup_connection() {
    reg_values.registration_process = 0;

    while (reg_values.registration_process < MAX_ATTEMPTS) {
        
        if (debug) { debug_message("New registration process started"); }
        set_initial_values();

        while (reg_values.sent_packages < MAX_PACKAGES) {
            struct package conf_package;
            conf_package = build_conf_package();

            if (reg_values.sent_packages >= PACKAGES_FOR_INC && reg_values.send_time < MAX_INTERVAL) {
                reg_values.send_time += SEND_INTERVAL;
            }

            int return_code;
            return_code = sendto(sock, &conf_package, sizeof(conf_package), 0, (struct sockaddr *) &udp_address, sizeof(udp_address));
            if (debug) print_send_message(conf_package);
            if (return_code < 0) {
                error_message("Could not send the register package");
            }
            if (debug) { debug_message("Registration request sent"); }
            if (state == DISCONNECTED) { change_state(WAIT_REG_RESPONSE); }

            struct package *recv_package;
            recv_package = receive_package();
            if (strcmp(recv_package -> random_number, "-1") != 0) {
                int recv_type = recv_package -> type;
                switch (recv_type) {
                    // REGISTER_REJ
                    case REGISTER_REJ:
                        reg_values.sent_packages = MAX_PACKAGES;
                        reg_values.registration_process = MAX_ATTEMPTS - 1;
                        change_state(DISCONNECTED);
                        if (debug) { debug_message("Process finished because a REGISTER_REJ package have been received"); }
                        
                        free(recv_package);
                        break;
                    
                    // REGISTER_NACK
                    case REGISTER_NACK:
                        reg_values.sent_packages = MAX_PACKAGES;

                        free(recv_package);
                        break;
                    
                    // REGISTER_ACK
                    case REGISTER_ACK:
                        reg_values.sent_packages = MAX_PACKAGES;
                        reg_values.registration_process = MAX_ATTEMPTS - 1;
                        change_state(REGISTERED);

                        strcpy(server_d.id, recv_package -> id);
                        strcpy(server_d.mac,recv_package -> mac);
                        tcp_sock.ip = atoi(recv_package -> random_number);
                        tcp_sock.port = atoi(recv_package -> data);
                        strcpy(server_d.rand_num, recv_package -> random_number);

                        free(recv_package);
                        break;
                    default:
                        error_message("The type of the package is not correct");
                        free(recv_package);
                }
            } else {error_message("Response have not been received");}

            if (reg_values.registration_process < MAX_ATTEMPTS && reg_values.sent_packages < MAX_PACKAGES){
                state = WAIT_REG_RESPONSE;
                reg_values.sent_packages++;
            }
        }
        reg_values.registration_process++;
        if (reg_values.registration_process < MAX_ATTEMPTS) { sleep(WAIT_TIME); }
    }

    if (state == WAIT_REG_RESPONSE) {
        error_message("Could not connect with the server");
    }
}

struct package build_conf_package() {
    struct package pck;
    
    memset(&pck, 0, sizeof(struct package));
    pck.type = REGISTER_REQ;
    strcpy(pck.id, client_d.id);
    strcpy(pck.mac, client_d.mac);
    strcpy(pck.random_number, "000000");
    strcpy(pck.data, "");

    return pck;
}

struct package build_not_received_package() {
    struct package pck;
    
    memset(&pck, 0, sizeof(struct package));
    pck.type = REGISTER_REQ;
    strcpy(pck.id, client_d.id);
    strcpy(pck.mac, client_d.mac);
    strcpy(pck.random_number, "-1");
    strcpy(pck.data, "");

    return pck;
}

void set_initial_values() {
    reg_values.send_time = SEND_INTERVAL;
    reg_values.sent_packages = 0;
}

struct package *receive_package() {
    struct package *recv_package = malloc(sizeof(struct package));
    fd_set fds;
    char *buf = malloc(sizeof(struct package));
    struct timeval time;
    time.tv_sec = reg_values.send_time;
    time.tv_usec = 0;
    int return_code;

    // Add socket to set
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    
    // Check if any data is in socket
    return_code = select(sock + 1, &fds, NULL, NULL, &time);
    if (return_code < 0) {
        error_message("Have been an error while receiving the udp message");
    } else if (return_code == 0) {
        // If have not received a package, return a package with rand_num = -1
        if (debug) { debug_message("Time expired while waiting for server response"); }
        struct package *pointer = malloc(sizeof(struct package));
        *pointer = build_not_received_package();
        return pointer;
    } else {
        // Receive from socket
        int num_bytes;
        num_bytes = recvfrom(sock, buf, sizeof(struct package), 0, (struct sockaddr *) 0, (socklen_t *) 0);
        if (num_bytes < 0) {
            error_message("Could not receive from socket");
        } else {
            recv_package = (struct package *) buf;

            if (debug) {
                char buffer[200];
    
                sprintf(buffer, "Package received:\n"
                        "\t\t\tType: 0x%X,\n"
                        "\t\t\tId: %s,\n "
                        "\t\t\tMac: %s,\n"
                        "\t\t\tRand num: %s,\n"
                        "\t\t\tData: %s",
                        (unsigned char) (*recv_package).type,
                        (*recv_package).id, (*recv_package).mac,
                        (*recv_package).random_number, (*recv_package).data);
                debug_message(buffer);
            }
        }
    }

    return recv_package;
}

void init_loop() {
    pthread_create(&thread, NULL, manage_command_line, NULL);

    send_alive();
}

void *manage_command_line() {
    while (true) {
        char *command = read_console(10);

        if (strcmp(command, "send-cfg") == 0) {
            send_conf_file();
        } else if (strcmp(command, "get-cfg") == 0) {
            get_conf_file();
        } else if (strcmp(command, "quit") == 0) {
            finalize_client();
        } else if (strlen(command) > 0) {
            print_message("Incorrect command. The valid commands are:\n"
                "\t\t\t- send-cfg\n"
                "\t\t\t- get-cfg\n"
                "\t\t\t- quit\n");
        }
    }
}

void send_conf_file() {
    FILE* file = fopen(conf_file_name, "r");
    if (file == NULL) {
        char *msg1 = "The file \"";
        char *msg2 = "\" doesn't exist";
        char buffer[strlen(msg1) + strlen(msg2) + strlen(conf_file_name)];
        sprintf(buffer, "%s%s%s", msg1, conf_file_name, msg2);
        warning_message(buffer);
        return;
    }

    print_message("Send request accepeted");

    setup_tcp_socket();

    // Send package
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    char data[150];
    sprintf(data, "%s,%li", conf_file_name, size);

    struct file_package pck = build_file_package(SEND_FILE, data);
    send_tcp_package(pck);

    // Check received package
    struct file_package *recv_pck = recv_file_package();
    char expected_data[150];
    sprintf(expected_data, "%s.cfg", client_d.id);

    if ((*recv_pck).type != SEND_ACK) {
        // Case rejected by server
        warning_message((*recv_pck).data);
        close(tcp_sock.socket);
        fclose(file);
        return;
    }

    if (strcmp((*recv_pck).random_number, "-1") == 0) {
        // Case response not received
        warning_message("No package received");
        close(tcp_sock.socket);
        fclose(file);
        return;
    }

    if (!valid_server_data_tcp(recv_pck) || !strcmp((*recv_pck).data, expected_data) == 0) {
        // Case invalid package received
        warning_message("The received package is not correct");
        close(tcp_sock.socket);
        fclose(file);
        return;
    }

    // Send lines with [SEND_DATA]
    rewind(file);
    char line[150];
    while (fgets(line, sizeof(line), file) != NULL) {
        pck = build_file_package(SEND_DATA, line);
        send_tcp_package(pck);
    }

    // Send [SEND_END] package
    pck = build_file_package(SEND_END, "");
    send_tcp_package(pck);

    close(tcp_sock.socket);
    fclose(file);
    print_message("Successfully ended sending configuration file");
}

void get_conf_file() {
    FILE* file = fopen(conf_file_name, "r+");
    if (file == NULL) {
        char *msg1 = "The file \"";
        char *msg2 = "\" doesn't exist";
        char buffer[strlen(msg1) + strlen(msg2) + strlen(conf_file_name)];
        sprintf(buffer, "%s%s%s", msg1, conf_file_name, msg2);
        warning_message(buffer);
        return;
    }

    print_message("Get request accepeted");

    setup_tcp_socket();

    // Send package
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    char data[150];
    sprintf(data, "%s,%li", conf_file_name, size);

    struct file_package pck = build_file_package(GET_FILE, data);
    send_tcp_package(pck);

    // Check received package
    struct file_package *recv_pck = recv_file_package();
    char expected_data[150];
    sprintf(expected_data, "%s.cfg", client_d.id);

    if ((*recv_pck).type != GET_ACK) {
        // Case rejected by server
        warning_message((*recv_pck).data);
        close(tcp_sock.socket);
        fclose(file);
        return;
    }

    if (strcmp((*recv_pck).random_number, "000000") == 0) {
        // Case response not received
        warning_message("No package received");
        close(tcp_sock.socket);
        fclose(file);
        return;
    }

    if (!valid_server_data_tcp(recv_pck) || !strcmp((*recv_pck).data, expected_data) == 0) {
        // Case invalid package received
        warning_message("The received package is not correct");
        close(tcp_sock.socket);
        fclose(file);
        return;
    }

    // Process [SEND_DATA] received packages
    rewind(file);
    while ((*recv_pck).type != GET_END) {
        recv_pck = recv_file_package();
        if (strcmp((*recv_pck).random_number, "000000") == 0) {
        // Response not received
            warning_message("No package received");
            close(tcp_sock.socket);
            fclose(file);
            return;
        }

        if ((*recv_pck).type == GET_DATA) {
            fputs((*recv_pck).data, file);
        } else if ((*recv_pck).type != GET_END) {
            warning_message("Incorrect package received while 'get-cfg'");
            close(tcp_sock.socket);
            fclose(file);
            return;
        }
    }

    close(tcp_sock.socket);
    fclose(file);
    print_message("Successfully ended the reception of configuration file");
}

struct file_package build_file_package(unsigned char type, char data[150]) {
    struct file_package pck;
    
    memset(&pck, 0, sizeof(struct file_package));
    pck.type = type;
    strcpy(pck.id, client_d.id);
    strcpy(pck.mac, client_d.mac);
    strcpy(pck.random_number, server_d.rand_num);
    strcpy(pck.data, data);

    return pck;
}

struct file_package build_empty_file_package() {
    struct file_package pck;
    
    memset(&pck, 0, sizeof(struct file_package));
    pck.type = 0x0F;
    strcpy(pck.id, client_d.id);
    strcpy(pck.mac, client_d.mac);
    strcpy(pck.random_number, "000000");

    return pck;
}

void send_tcp_package(struct file_package pck) {
    if (write(tcp_sock.socket, &pck, sizeof(pck)) == -1) {
        error_message("Could not send TCP package");
    } else if (debug) {
        char buffer[300];
    
        sprintf(buffer, "Package sent:\n"
            "\t\t\tType: 0x%X,\n"
            "\t\t\tId: %s,\n "
            "\t\t\tMac: %s,\n"
            "\t\t\tRand num: %s,\n"
            "\t\t\tData: %s",
            (unsigned char) pck.type,
            pck.id, pck.mac,
            pck.random_number, pck.data);
        debug_message(buffer);
    }
}

struct file_package *recv_file_package() {
    struct file_package *recv_package = malloc(sizeof(struct file_package));
    fd_set fds;
    char *buf = malloc(sizeof(struct file_package));
    struct timeval time;
    time.tv_sec = MAX_TCP_TIME;
    time.tv_usec = 0;
    int return_code;
    
    // Add socket to set
    FD_ZERO(&fds);
    FD_SET(tcp_sock.socket, &fds);
    
    // Check if any data is in socket
    return_code = select(tcp_sock.socket + 1, &fds, NULL, NULL, &time);
    if (return_code < 0) {
        error_message("Have been an error while receiving the tcp message");
    } else if (return_code == 0) {
        // If have not received a package, return a package with rand_num = 0
        if (debug) { debug_message("Time expired while waiting for server response"); }
        struct file_package *pointer = malloc(sizeof(struct file_package));
        *pointer = build_empty_file_package();
        return pointer;
    } else {
        // Receive from socket
        read(tcp_sock.socket, buf, sizeof(struct file_package));
        recv_package = (struct file_package *) buf;

        if (debug) {
            char buffer[300];
    
            sprintf(buffer, "Package received:\n"
                    "\t\t\tType: 0x%X,\n"
                    "\t\t\tId: %s,\n "
                    "\t\t\tMac: %s,\n"
                    "\t\t\tRand num: %s,\n"
                    "\t\t\tData: %s",
                    (unsigned char) (*recv_package).type,
                    (*recv_package).id, (*recv_package).mac,
                    (*recv_package).random_number, (*recv_package).data);
            debug_message(buffer);
        }
    }

    return recv_package;
}

char *read_console(int max_chars_to_read) {
    char buffer[max_chars_to_read];
    if (fgets(buffer, max_chars_to_read, stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';
    }
    char *buffer_pointer = malloc(max_chars_to_read);
    strcpy(buffer_pointer, buffer);
    return buffer_pointer;
}

void send_alive() {
    int consecutive_non_received_ack = 0;
    bool finish_bucle = false;
    struct package alive_pck = build_alive_package();

    // Send alives while connected with the server
    while (!finish_bucle) {
        if (consecutive_non_received_ack < MAX_NON_RECEIBED_ACK) {
            sendto(sock, &alive_pck, sizeof(alive_pck), 0, (struct sockaddr *) &udp_address, sizeof(udp_address));
            if (debug) print_send_message(alive_pck);
            struct package *recv_package;
            recv_package = receive_package();
            if (strcmp(recv_package -> random_number, "000000") == 0 || recv_package -> type == 20 || !valid_server_data_udp(recv_package)) {
                // Package not received or ignored
                consecutive_non_received_ack++;
                if (debug) {
                    char *msg = "Consecutive non received packages: ";
                    char buffer[strlen(msg) + 4];
                    sprintf(buffer, "%s%i", msg, consecutive_non_received_ack);
                    debug_message(buffer);
                }
            } else if (recv_package -> type == 22) {
                // ALIVE_ACK rejected
                finish_bucle = true;
            } else {
                // ALIVE_ACK received
                if (state != SEND_ALIVE) {
                    change_state(SEND_ALIVE);
                }
                consecutive_non_received_ack = 0;
            }

            free(recv_package);
            sleep(ALIVE_FREQUENCY);
        } else {
            finish_bucle = true;
        }
    }
    
    change_state(DISCONNECTED);
    setup_connection();
}

struct package build_alive_package() {
    struct package pck;
    
    memset(&pck, 0, sizeof(struct package));
    pck.type = ALIVE_INF;
    strcpy(pck.id, client_d.id);
    strcpy(pck.mac, client_d.mac);
    strcpy(pck.random_number, server_d.rand_num);

    return pck;
}

bool valid_server_data_udp(struct package *package) {
    bool correct_rand_num;
    bool correct_server_id;
    bool correct_server_mac;
    
    correct_rand_num = strcmp((*package).random_number, server_d.rand_num) == 0;
    correct_server_id = strcmp((*package).id, server_d.id) == 0;
    correct_server_mac = strcmp((*package).mac, server_d.mac) == 0;

    return correct_rand_num && correct_server_id && correct_server_mac;
}

bool valid_server_data_tcp(struct file_package *package) {
    bool correct_rand_num;
    bool correct_server_id;
    bool correct_server_mac;
    
    correct_rand_num = strcmp((*package).random_number, server_d.rand_num) == 0;
    correct_server_id = strcmp((*package).id, server_d.id) == 0;
    correct_server_mac = strcmp((*package).mac, server_d.mac) == 0;

    return correct_rand_num && correct_server_id && correct_server_mac;
}